/*
 * utils.cpp
 * Auxiliary functions for crxprof
 */
#include <stdarg.h>
#include <stdio.h>
#include "crxprof.hpp"

#define RESET_COLOR "\e[m"
#define RED_COLOR "\e[31m"

void
print_message(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    printf(RED_COLOR);
    vprintf(fmt, ap);
    printf(RESET_COLOR "\n");
    va_end(ap);
}
