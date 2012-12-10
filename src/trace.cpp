#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <endian.h>
#include <string.h>
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


static uint64_t read_schedstat(const ptrace_context &ctx);
static int wait4stop(pid_t pid);
static const fn_descr *lookup_fn_descr(long ip, const std::vector<fn_descr> &funcs);
static int get_backtrace(struct ptrace_context *ctx, unw_word_t *ips, int max_depth);

static int wait4stop(pid_t pid)
{
    int status;
    
    do {
        if (waitpid(pid, &status, 0) == -1 || 
            WIFEXITED(status) || WIFSIGNALED(status)) {
            return 0;
        }
    } while( !WIFSTOPPED(status) );

    return 1;
}

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


void attach_process(pid_t pid, struct ptrace_context *ctx)
{
    ctx->pid = pid;
    ctx->addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!ctx->addr_space)
        err(EXIT_FAILURE, "Failed to create address space");

    unw_set_caching_policy(ctx->addr_space, UNW_CACHE_GLOBAL);
    ctx->unwind_rctx = _UPT_create(ctx->pid);
    if (!ctx->unwind_rctx)
        err(EXIT_FAILURE, "_UPT_create failed");

    if ( -1 == ptrace(PTRACE_ATTACH, pid, NULL, NULL) )
        err(1, "ptrace(PTRACE_ATTACH, %d) failed", pid);

    /* Since ptrace stops process, wait it and continue.
     * We will STOP it by timer (via SIGSTOP)
     */
    if (!wait4stop(ctx->pid))
        err(1, "wait SIGSTOP of ptrace failed");

    ptrace(PTRACE_CONT, ctx->pid, 0, 0);


    sprintf(ctx->procstat_path, "/proc/%d/stat", ctx->pid);
    sprintf(ctx->schedstat_path, "/proc/%d/schedstat", ctx->pid);
    ctx->saved_cputime = read_schedstat(*ctx);
}

static int get_backtrace(struct ptrace_context *ctx, unw_word_t *ips, int max_depth)
{
    unw_cursor_t resume_cursor, cursor;

    kill(ctx->pid, SIGSTOP);
    if (!wait4stop(ctx->pid))
        err(1, "wait SIGSTOP of ptrace failed");

    if (unw_init_remote(&cursor, ctx->addr_space, ctx->unwind_rctx))
        err(1, "unw_init_remote failed");

    resume_cursor = cursor;
    
    int depth = 0;
    do {
        unw_get_reg(&cursor, UNW_REG_IP, &ips[depth++]);
    } while (depth < max_depth && unw_step(&cursor) > 0);

    /* resume execution at top frame */
    _UPT_resume(ctx->addr_space, &resume_cursor, ctx->unwind_rctx);

    return depth;
}


void fill_backtrace(unsigned cost, struct ptrace_context *ctx, 
                    const std::vector<fn_descr> &funcs, calltree_node **root)
{
    static unw_word_t ips[MAX_STACK_DEPTH];
    int depth = get_backtrace(ctx, &ips[0], MAX_STACK_DEPTH);

    if (depth == MAX_STACK_DEPTH) {
        // too small size of ips. So, we don't have start frame here.
        // Simply ignore
        return;
    }

    calltree_node *parent = NULL;
    for (--depth; depth >= 0; depth--) {
        const fn_descr *pfn = lookup_fn_descr(ips[depth], funcs);
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
}

/* format of /proc/$pid/schedstat:
 * cputime_ns iowait_ns nswitches
 */
static uint64_t
read_schedstat(const ptrace_context &ctx)
{
    uint64_t us = -1U;
    int fd = open(ctx.schedstat_path, O_RDONLY);

    if (fd != -1) {
        static char buf[20];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 2) {
            char *pend = (char *)memchr(buf, ' ', n);
            if (pend) {
                *pend = '\0';
                us = strtoll(buf, NULL, 10) / 1000;
            }
        }
        close(fd);
    }

    return us;
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

unsigned
get_cpudiff_us(ptrace_context *ctx)
{
    uint64_t cur_cputime = read_schedstat(*ctx);
    uint64_t diff_cputime = cur_cputime - ctx->saved_cputime;

    ctx->saved_cputime = cur_cputime;
    return diff_cputime;
}
