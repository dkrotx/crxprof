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
#include <sys/stat.h>
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
    *key_pressed = false;

    if (isatty(STDIN_FILENO)) {
        fd_set fds;

        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);

        if (select(STDIN_FILENO+1, &fds, NULL, NULL, NULL /* timeout = infinite */) == 1) {
            static char buf[16];
            int nb;

            assert( FD_ISSET(STDIN_FILENO, &fds) );
            *key_pressed = true;

            if (ioctl(STDIN_FILENO, FIONREAD, &nb) == -1) {
                warn("ioctl STDIN_FILENO failed");
                return;
            }

            /* simply discard all data */
            while(nb) {
                ssize_t nr = read(STDIN_FILENO, buf, nb > sizeof(buf) ? sizeof(buf) : nb);
                if (nr <= 0)
                    return;
                nb -= nr;
            }
       }
    }
    else {
        select(0, NULL, NULL, NULL, NULL); /* simply sleep if non-terminal */
    }
}

bool
has_openvz()
{
    struct stat st;
    return stat("/proc/vz", &st) == 0;
}
