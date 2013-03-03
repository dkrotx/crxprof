/*
 * utils.c
 * Auxiliary functions for crxprof
 */
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <err.h>

#include "crxprof.h"

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


/**
 * sleeping loop. Sleep on select(2) but awake on keypress (ENTER).
 * Since user may press several characters before ENTER, we have 
 * to discard 'em all
 */
void
wait4keypress(bool *key_pressed)
{
    static fd_set fds;
    static bool first_time = true;

    if (first_time) {
        FD_ZERO(&fds);
        first_time = false;
    }
    
    FD_SET(STDIN_FILENO, &fds);
    if (select(STDIN_FILENO+1, &fds, NULL, NULL, NULL /* timeout = infinite */) == 1) {
        static char buf[16];
        ssize_t nr;
        size_t  nb;

        assert( FD_ISSET(STDIN_FILENO, &fds) );
        *key_pressed = true;

        if (ioctl(STDIN_FILENO, FIONREAD, &nb) == -1) {
            warn("ioctl STDIN_FILENO failed");
            return;
        }
    
        /* simply discard all data */
        while(nb) {
            nr = read(STDIN_FILENO, buf, nb & (16-1));
            if (nr <= 0)
                return;
            nb -= nr;
        }
   }

   *key_pressed = false;
}
