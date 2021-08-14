#include <stdio.h>

#define FUNC_SYMBOL(NAME) \
    int NAME(int x) \
    { \
        printf("This is function " #NAME ", and it's supplied x=%d", x); \
        return x; \
    }

#define VAR_SYMBOL(NAME, VALUE) \
    int NAME = VALUE;

#include "./generated_symbols.txt"

int main(void)
{
    puts("Hello! this is a test application.");

}
