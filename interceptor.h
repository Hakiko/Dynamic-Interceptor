#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

void *intercept_function(const char *name, void *new_func);
void unintercept_function(const char *name);

#ifdef __cplusplus
}
#endif

#endif
