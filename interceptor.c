#define _GNU_SOURCE
#include "interceptor.h"

#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef ELF_R_SYM
#if __ELF_NATIVE_CLASS == 64
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELF_R_SYM ELF32_R_SYM
#endif
#endif

struct intercept_ctx_t {
  const char *str_tab_addr;
  const ElfW(Sym) * sym_tab_addr;
  const ElfW(Rela) * rela_tab_addr;
  size_t str_tab_size;
  size_t rela_tab_size;
  const char *tgt_name;
  void *tgt_ptr;
};

static void intercept_ctx_init(struct intercept_ctx_t *obj,
                               const char *tgt_name, void *tgt_ptr) {
  obj->str_tab_addr = NULL;
  obj->sym_tab_addr = NULL;
  obj->rela_tab_addr = NULL;
  obj->str_tab_size = 0;
  obj->rela_tab_size = 0;
  obj->tgt_name = tgt_name;
  obj->tgt_ptr = tgt_ptr;
}

static int intercept_ctx_ok(struct intercept_ctx_t *obj) {
  if (obj->rela_tab_addr == NULL) {
    return 0;
  }
  if (obj->str_tab_addr == NULL) {
    return 0;
  }
  if (obj->sym_tab_addr == NULL) {
    return 0;
  }
  return 1;
}

struct intercept_call_t {
  const char *name;
  void *pointer;
};

static void intercept_call_init(struct intercept_call_t *obj, const char *name,
                                void *ptr) {
  obj->name = name;
  obj->pointer = ptr;
}

static void dynamic_element_callback(const ElfW(Dyn) * element,
                                     struct intercept_ctx_t *ctx) {
  if (element->d_tag == DT_STRTAB) {
    const char *addr = (const char *)element->d_un.d_ptr;
    ctx->str_tab_addr = addr;
  } else if (element->d_tag == DT_STRSZ) {
    size_t sz = element->d_un.d_val;
    ctx->str_tab_size = sz;
  } else if (element->d_tag == DT_SYMTAB) {
    const ElfW(Sym) *addr = (const ElfW(Sym) *)element->d_un.d_ptr;
    ctx->sym_tab_addr = addr;
  } else if (element->d_tag == DT_JMPREL) {
    const ElfW(Rela) *addr = (const ElfW(Rela) *)element->d_un.d_ptr;
    ctx->rela_tab_addr = addr;
  } else if (element->d_tag == DT_PLTRELSZ) {
    size_t sz = element->d_un.d_val;
    ctx->rela_tab_size = sz;
  }
}

static void section_callback(const ElfW(Phdr) * section,
                             ElfW(Addr) base_address,
                             struct intercept_ctx_t *ctx) {
  if (section->p_type == PT_DYNAMIC) {
    ElfW(Addr) loc = base_address + section->p_vaddr;
    size_t elem_count = section->p_memsz / sizeof(ElfW(Dyn));
    ElfW(Dyn) *elements = (ElfW(Dyn) *)loc;
    size_t i;
    for (i = 0; i < elem_count; ++i) {
      dynamic_element_callback(&elements[i], ctx);
    }
  }
}

static int lift_mprotect(void *addr) {
  return mprotect((void *)(((unsigned long long)addr) & (~4095ULL)), 4096ULL,
                  PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void change_relocations(struct intercept_ctx_t *ctx,
                               ElfW(Addr) base_addr) {
  if (intercept_ctx_ok(ctx)) {
    const ElfW(Rela) *rel = ctx->rela_tab_addr;
    size_t relocation_count = ctx->rela_tab_size / sizeof(ElfW(Rela));
    for (size_t j = 0; j < relocation_count; ++j) {
      ElfW(Rela) r = rel[j];
      ElfW(Xword) r_sym = ELF_R_SYM(r.r_info);
      ElfW(Sym) sym = ctx->sym_tab_addr[r_sym];
      const char *sym_name = ctx->str_tab_addr + sym.st_name;
      if (strcmp(ctx->tgt_name, sym_name) == 0) {
        void *rel_addr = (void *)r.r_offset;
        int res = lift_mprotect(rel_addr);
        if (res == -1) {
          rel_addr = (void *)(r.r_offset + base_addr);
          res = lift_mprotect(rel_addr);
        }
        if (res == -1) {
          fprintf(stderr, "error in lift_mprotect: %s\n", strerror(errno));
        } else {
          void **tgt_loc = (void **)(rel_addr);
          *(tgt_loc) = ctx->tgt_ptr;
        }
      }
    }
  }
}

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size;
  struct intercept_ctx_t context;
  struct intercept_call_t *call = data;
  intercept_ctx_init(&context, call->name, call->pointer);
  int i;
  for (i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *hdr_data = &(info->dlpi_phdr[i]);
    section_callback(hdr_data, info->dlpi_addr, &context);
  }
  change_relocations(&context, info->dlpi_addr);
  return 0;
}

struct restore_list_t {
  struct restore_list_t *next;
  void *original;
  const char *name;
};

static struct restore_list_t *restore_list_alloc(void *orig, const char *name) {
  struct restore_list_t *node = malloc(sizeof(struct restore_list_t));
  node->next = NULL;
  node->original = orig;
  node->name = name;
  return node;
}

static void restore_list_free(struct restore_list_t *lst) { free(lst); }

static struct restore_list_t *root_restore;

static struct restore_list_t *push_restore(void *orig, const char *name,
                                           struct restore_list_t *lst) {
  struct restore_list_t *link = lst;
  while (link) {
    if (strcmp(name, link->name) == 0) {
      return lst;
    }
    link = link->next;
  }
  link = restore_list_alloc(orig, name);
  link->next = lst;
  return link;
}

static struct restore_list_t *pop_restore(const char *name, void **addr,
                                          struct restore_list_t *lst) {
  struct restore_list_t **own = &lst;
  while (*own) {
    if (strcmp(name, (*own)->name) == 0) {
      struct restore_list_t *tmp = *own;
      if (addr) {
        *addr = (tmp->original);
      }
      *own = tmp->next;
      restore_list_free(tmp);
      break;
    }
    own = &(*own)->next;
  }
  return lst;
}

void *intercept_function(const char *name, void *new_func) {
  void *dlsym_res = dlsym(RTLD_NEXT, name);
  struct intercept_call_t call;
  intercept_call_init(&call, name, new_func);
  dl_iterate_phdr(phdr_callback, (void *)&call);
  root_restore = push_restore(dlsym_res, name, root_restore);
  return dlsym_res;
}

void unintercept_function(const char *name) {
  void *orig = NULL;
  root_restore = pop_restore(name, &orig, root_restore);
  if (orig) {
    intercept_function(name, orig);
  }
}
