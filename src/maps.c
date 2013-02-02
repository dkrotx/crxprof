/*
 * maps.c
 *
 * Parse data from /proc/pid/maps
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "symbols.h"
/*
 *    The format is:
 *
 *    address           perms offset  dev   inode   pathname
 *    08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
 *    08056000-08058000 rw-p 0000d000 03:0c 64593   /usr/sbin/gpm
 *    08058000-0805b000 rwxp 00000000 00:00 0
 *    40000000-40013000 r-xp 00000000 03:0c 4165    /lib/ld-2.2.4.so
 *    40013000-40015000 rw-p 00012000 03:0c 4165    /lib/ld-2.2.4.so
 *    4001f000-40135000 r-xp 00000000 03:0c 45494   /lib/libc-2.2.4.so
 *    40135000-4013e000 rw-p 00115000 03:0c 45494   /lib/libc-2.2.4.so
 *    4013e000-40142000 rw-p 00000000 00:00 0
 *    bffff000-c0000000 rwxp 00000000 00:00 0
 */


struct maps_ctx *
maps_fopen(pid_t pid)
{
    struct maps_ctx *ctx;
    char path[32];

    sprintf(path, "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;

    ctx = (struct maps_ctx *)malloc(sizeof(struct maps_ctx));
    if (ctx) {
        ctx->linebuf = 0;
        ctx->linebuf_size = 0;
        ctx->procfile = f;
    }
    return ctx;
}


struct maps_info*
maps_readnext(struct maps_ctx *ctx)
{
    int nconsumed = 0;
    ssize_t n;
    long long unsigned int offset, inode;
    char prot_str[4];
    int dev_maj, dev_min;
    void *start_addr, *end_addr;

    n = getline(&ctx->linebuf, &ctx->linebuf_size, ctx->procfile);
    if (n < 0 || (n == 0 && !feof(ctx->procfile)) || feof(ctx->procfile))
        return (struct maps_info *)NULL;

    /* trim \n et the end */
    ctx->linebuf[n - 1] = '\0';

    if (sscanf(ctx->linebuf, "%p-%p %4c %llx %x:%x %llu%n", 
          &start_addr, &end_addr,
          &prot_str[0], &offset,
          &dev_maj, &dev_min, &inode, &nconsumed) >= 7)
    {
        struct maps_info *pvi;
        char *pname;
        size_t namelen;

        assert(nconsumed);

        pname = ctx->linebuf + nconsumed;
        while (isblank(*pname))
            pname++;

        namelen = strlen(pname);
        pvi = (struct maps_info *)malloc(sizeof(struct maps_info) +
               namelen + 1 /* null-byte */);

        pvi->start_addr = start_addr;
        pvi->end_addr = end_addr;
        pvi->prot = 0;

        if (prot_str[0] == 'r')
            pvi->prot |= PROT_READ;
        if (prot_str[1] == 'w')
            pvi->prot |= PROT_WRITE;
        if (prot_str[2] == 'x')
            pvi->prot |= PROT_EXEC;

        if (prot_str[3] == 'p')
            pvi->flags = MAP_PRIVATE;
        else
            pvi->flags = MAP_SHARED;


        pvi->offset = offset;
        pvi->st_dev = makedev(dev_maj, dev_min);
        pvi->st_ino = inode;
        memcpy(pvi->pathname, pname, namelen);
        pvi->pathname[namelen] = '\0';

        return pvi;
    }

    return (struct maps_info *)NULL;
}


void
maps_close(struct maps_ctx *ctx)
{
    if (ctx->linebuf) {
        free(ctx->linebuf);
        ctx->linebuf = NULL;
    }
    if (ctx->procfile) {
        fclose(ctx->procfile);
        ctx->procfile = NULL;
    }

    free(ctx);
}


/*
 * For most files under the /proc directory, stat() does not return the file size in the st_size field
 * So, use pretty old PATH_MAX
 */
char *
proc_get_exefilename(pid_t pid)
{
    char exepath[sizeof("/proc/4000000000/exe")];
    char *linkname;
    ssize_t r;

    sprintf(exepath, "/proc/%d/exe", pid);
    
    linkname = malloc(PATH_MAX + 1);
    if (!linkname)
        return NULL;

    r = readlink(exepath, linkname, PATH_MAX);
    if (r < 0) {
        free(linkname);
        return NULL;
    }

    linkname[r] = '\0';
    return linkname;
}
