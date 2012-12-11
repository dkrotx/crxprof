#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <endian.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <err.h>
#include "crxprof.hpp"

#include <libunwind-ptrace.h>
#include <algorithm>

struct addr_comparator
{
    const fn_descr *pfn;

    addr_comparator(const fn_descr *a_pfn) : pfn(a_pfn) {}
    bool operator ()(const calltree_node *pelem) const {
        return pelem->pfn == pfn;
    }
};


static const fn_descr *
lookup_fn_descr(long ip, const std::vector<fn_descr> &funcs)
{
    int l = 0, h = funcs.size();
    while(l < h) {
        int i = (l + h)/2;
        if (ip < funcs[i].addr) {
            h = i;
        }
        else if (ip >= (funcs[i].addr + funcs[i].len))
            l = i + 1;
        else
            return &funcs[i];
    }

    return NULL;
}


bool
trace_init(pid_t pid, struct ptrace_context *ctx)
{
    ctx->pid = pid;
    ctx->addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!ctx->addr_space)
        return false;

    unw_set_caching_policy(ctx->addr_space, UNW_CACHE_GLOBAL);
    ctx->unwind_rctx = _UPT_create(ctx->pid);
    if (!ctx->unwind_rctx)
        return false;

    if (clock_getcpuclockid(pid, &ctx->clock_id) != 0)
        return false;

    sprintf(ctx->procstat_path, "/proc/%d/stat", pid);
    return true;
}


uint64_t
get_cputime_ns(struct ptrace_context *ctx)
{
    struct timespec ts;

    if (clock_gettime(ctx->clock_id, &ts) == -1) 
        return -1;
    return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}

bool
get_backtrace(struct ptrace_context *ctx)
{
    struct trace_stack *pstk = &ctx->stk;
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
fill_backtrace(uint64_t cost, const struct trace_stack &stk, 
               const std::vector<fn_descr> &funcs, calltree_node **root)
{
    if (stk.depth == 0 || stk.depth >= MAX_STACK_DEPTH) {
        // too small size of ips. So, we don't have start frame here.
        // Simply ignore
        return false;
    }

    calltree_node *parent = NULL;
    int depth = stk.depth - 1;
    while (depth >= 0) {
        const fn_descr *pfn = lookup_fn_descr(stk.ips[depth--], funcs);
        if (pfn)
        {
            if (parent) {
                calltree_node *this_node;

                parent->nintermediate += cost;
                siblings_t::iterator it = 
                    std::find_if(parent->childs.begin(), parent->childs.end(), addr_comparator(pfn));

                if (it == parent->childs.end()) {
                    this_node = new calltree_node(pfn);
                    parent->childs.push_back(this_node);
                }
                else {
                    this_node = *it;
                }

                parent = this_node;
            }
            else
            {
                if (!*root)
                    parent = *root = new calltree_node(pfn);

                else if (pfn == (*root)->pfn)
                    parent = *root;
            }
        }
    }

    if (parent)
        parent->nself += cost;

    return true;
}


char
get_procstate(const ptrace_context &ctx)
{
    char ret = 0;
    int fd = open(ctx.procstat_path, O_RDONLY);

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
