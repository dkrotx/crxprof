#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <endian.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include "crxprof.h"

#include <libunwind-ptrace.h>

static const fn_descr *
lookup_fn_descr(unsigned long ip)
{
    int l = 0, h = g_nfndescr;

    while(l < h) {
        int i = (l + h)/2;
        if (ip < g_fndescr[i].addr) {
            h = i;
        }
        else if (ip >= (g_fndescr[i].addr + g_fndescr[i].len))
            l = i + 1;
        else
            return &g_fndescr[i];
    }

    return NULL;
}


bool
trace_init(pid_t pid, ptrace_context *ctx) {
    ctx->pid = pid;
    ctx->addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!ctx->addr_space)
        return false;

    unw_set_caching_policy(ctx->addr_space, UNW_CACHE_GLOBAL);
    ctx->unwind_rctx = _UPT_create(ctx->pid);
    if (!ctx->unwind_rctx)
        return false;

    sprintf(ctx->procstat_path, "/proc/%d/stat", pid);
    return true;
}


void
trace_free(ptrace_context *ctx) {
    _UPT_destroy(ctx->unwind_rctx);
    unw_destroy_addr_space(ctx->addr_space);
}


bool
get_backtrace(ptrace_context *ctx) {
    trace_stack *pstk = &ctx->stk;
    unw_cursor_t cursor;
    pstk->depth = 0;

    if (unw_init_remote(&cursor, ctx->addr_space, ctx->unwind_rctx))
        return false;

    do {
        unw_get_reg(&cursor, UNW_REG_IP, &pstk->ips[pstk->depth++]);
    } while (pstk->depth < MAX_STACK_DEPTH && unw_step(&cursor) > 0);

    return true;
}


bool
fill_backtrace(uint64_t cost, const trace_stack *stk, 
               calltree_node **root)
{
    calltree_node *parent = NULL;
    int depth = stk->depth - 1;

    if (stk->depth <= 0 || stk->depth >= MAX_STACK_DEPTH) {
        // too small size of ips. So, we don't have start frame here.
        // Simply ignore
        return false;
    }

    while (depth >= 0) {
        const fn_descr *pfn = lookup_fn_descr(stk->ips[depth--]);
        if (pfn) {
            if (parent) {
                calltree_node *this_node = NULL;
                int i;

                for (i = 0; i < parent->nchilds; i++)
                    if (parent->childs[i].pfn == pfn) {
                        this_node = &parent->childs[i];
                        break;
                    }

                if (!this_node) {
                    parent->childs = (calltree_node *)realloc(parent->childs, 
                        sizeof(calltree_node) * ++parent->nchilds);
                    this_node = &parent->childs[parent->nchilds - 1];
                    memset(this_node, 0, sizeof(calltree_node));
                    this_node->pfn = pfn;
                }

                parent->nintermediate += cost;
                parent = this_node;
            }
            else {
                if (!*root) {
                    *root = calloc(1, sizeof(calltree_node));
                    assert(*root);
                    (*root)->pfn = pfn;
                    parent = *root;
                }
                else if (pfn == (*root)->pfn)
                    parent = *root;
            }
        }
    }

    if (parent)
        parent->nself += cost;

    return true;
}

static void
calltree_destroy_childs(calltree_node *root) {
    if (root->nchilds) {
        int i;
        for (i = 0; i < root->nchilds; i++) {
            calltree_destroy_childs(&root->childs[i]);
        }
        free(root->childs);
    }
}


void
calltree_destroy(calltree_node *root) {
    calltree_destroy_childs(root);
    free(root);
}

char
get_procstate(const ptrace_context *ctx) {
    char ret = 0;
    int fd = open(ctx->procstat_path, O_RDONLY);

    if (fd != -1) {
        static char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf));

        if(n > 7) {
            char *pend = (char *)memchr(buf, ')', n);
            if (pend && n - (pend - &buf[0]) >= 2)
                ret = *(pend + 2);
        }
        close(fd);
    }

    return ret;
}
