/*
 * utils.c
 * Auxiliary functions for crxprof
 */
#include <stdarg.h>
#include <stdio.h>

void
print_message(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    printf("--- ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}
