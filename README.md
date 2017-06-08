For every dynamic object loaded into the program, intercept_function() searches for the string table, the symbol table and the relocation table.

Then, change_relocations() substitutes the address at the relocation target with the user function.

Before returning, intercept_function() stores the location and the original address of the function in a global list.

The result of intercept_function() is an original address of the function acquired through the use of dlsym() with the RTLD_NEXT handle.

unintercept_function() first pops the address of the original function from the global list and calls intercept_function() to restore the original redirections.