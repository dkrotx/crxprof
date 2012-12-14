/*
 * main.cpp
 *
 * Entry point of crxprof. Parse arguments and collect symbols of given process (ID).
 */

#define __STDC_FORMAT_MACROS

#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <time.h>
#include <inttypes.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <getopt.h>
#include <err.h>

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>


#include "crxprof.hpp"
#include "symbols.h"

struct timeval tv_last_sigint = {0, 0};
static volatile bool sigint_caught = false;
static volatile bool timer_alarmed = false;
static volatile bool sigint_caught_twice = false;

static char *g_progname;

void
on_sigint(int)
{
    struct timeval tv, tv_diff;
    gettimeofday(&tv, NULL);

    sigint_caught  = true;
   
    timersub(&tv, &tv_last_sigint, &tv_diff);
    if (!tv_diff.tv_sec && tv_diff.tv_usec < 333000)
        sigint_caught_twice = true;

    tv_last_sigint = tv;
}

void
on_sigalarm(int)
{
    timer_alarmed = true;
}

void
on_sigchld(int)
{
    /* just for hang up */
}



#define FREQ_2PERIOD_USEC(n) ( 1000000 / (n) )

struct program_params
{
    unsigned us_sleep;
    int pid;
    vproperties vprops;
    const char *dumpfile;
    crxprof_method prof_method;
    bool just_print_symbols;

    program_params() : us_sleep(FREQ_2PERIOD_USEC(DEFAULT_FREQ)), 
                       dumpfile(NULL), prof_method(PROF_CPUTIME),
                       just_print_symbols(false) {}
};


typedef enum { WR_NOTHING, WR_FINISHED, WR_DETACHED, WR_STOPPED } waitres_t;
static waitres_t do_wait(ptrace_context *ctx, bool blocked);
static waitres_t discard_wait(ptrace_context *ctx);

static void dump_profile(const std::vector<fn_descr> &funcs, calltree_node *root, const char *filename);
static void read_symbols(pid_t pid, std::vector<fn_descr> *funcs);
static void print_symbols(const std::vector<fn_descr> &fns);
static bool parse_args(program_params *params, int argc, char **argv);
static void usage();

#define DMGL_AUTO        (1 << 8)
#define AUTO_DEMANGLING DMGL_AUTO
extern "C" 
{
  extern char *cplus_demangle (const char *mangled, int options);
}

int
main(int argc, char *argv[])
{
    std::vector<fn_descr> funcs;
    ptrace_context ptrace_ctx;
    program_params params;
    struct itimerval itv;

    g_progname = argv[0];
    if (!parse_args(&params, argc, argv))
        usage();

    print_message("Reading symbols (list of function)");
    read_symbols(params.pid, &funcs);
    if (params.just_print_symbols) {
        print_symbols(funcs);
        exit(0);
    }

    calltree_node *root = NULL;

    print_message("Attaching to process: %d", params.pid);
    memset(&ptrace_ctx, 0, sizeof(ptrace_ctx));
    if (!trace_init(params.pid, &ptrace_ctx))
        err(1, "Failed to initialize unwind internals");

    ptrace_ctx.prev_cputime = get_cputime_ns(&ptrace_ctx);
    signal(SIGCHLD, on_sigchld);
    if (ptrace(PTRACE_ATTACH, params.pid, 0, 0) == -1)
        err(1, "ptrace(PTRACE_ATTACH) failed");

    {
        do_wait(&ptrace_ctx, true);
        printf("STOPPED AT START\n");
        ptrace(PTRACE_CONT, params.pid, 0, 0);
    }


    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = params.us_sleep;
    itv.it_value = itv.it_interval;

    signal(SIGALRM, on_sigalarm);
    if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
        err(1, "setitimer failed");

    print_message("Starting profile (interval %dms)", params.us_sleep / 1000);
    print_message("Press ^C once to show profile, twice to quit");
    signal(SIGINT, on_sigint);

    for(;;) {
        waitres_t wres = WR_NOTHING;
        sleep(1);
        
        if (timer_alarmed) {
            uint64_t cpu_time = get_cputime_ns(&ptrace_ctx);
            bool need_prof = (params.prof_method == PROF_REALTIME);

            if (params.prof_method == PROF_CPUTIME) {
                char st = get_procstate(ptrace_ctx);
                if (st == 'R')
                    need_prof = true;
            }

            if (need_prof) {
                kill(params.pid, SIGSTOP);
                wres = do_wait(&ptrace_ctx, true);
                if (wres == WR_STOPPED) {
                    int signo_cont = (ptrace_ctx.stop_info.si_pid == getpid()) ? 0 : ptrace_ctx.stop_info.si_signo;

                    if (!get_backtrace(&ptrace_ctx))
                        err(2, "failed to get backtrace of process");

                    /* continue tracee ASAP */
                    if (ptrace(PTRACE_CONT, params.pid, 0, signo_cont) < 0)
                        err(1, "ptrace(PTRACE_CONT) failed");

                    if (fill_backtrace(cpu_time - ptrace_ctx.prev_cputime, ptrace_ctx.stk, funcs, &root))
                        ptrace_ctx.nsnaps_accounted++;
                }
                else if (wres == WR_DETACHED) {
                    ptrace(PTRACE_CONT, params.pid, 0, ptrace_ctx.stop_info.si_signo);
                }
                ptrace_ctx.nsnaps++;
            }

            ptrace_ctx.prev_cputime = cpu_time;
        }

        if (wres != WR_FINISHED && wres != WR_DETACHED) {
            wres = discard_wait(&ptrace_ctx);
        }

        if (sigint_caught_twice) {
            print_message("Exit");
            exit(0);
        }

        if (sigint_caught || wres == WR_FINISHED || wres == WR_DETACHED) {
            if (root) {
                print_message("%" PRIu64 " snapshot interrputs got (%" PRIu64 " dropped)", 
                    ptrace_ctx.nsnaps, ptrace_ctx.nsnaps - ptrace_ctx.nsnaps_accounted);

                visualize_profile(root, params.vprops);
                if (params.dumpfile)
                    dump_profile(funcs, root, params.dumpfile);
            } else
                print_message("No symbolic snapshot caught yet!");

            sigint_caught = false;
            root = NULL; // TODO: clear 
            ptrace_ctx.nsnaps = ptrace_ctx.nsnaps_accounted = 0;
        }

        if (wres == WR_FINISHED || wres == WR_DETACHED) {
            if (wres == WR_DETACHED) {
                printf("DETACHED\n");
                (void)ptrace(PTRACE_DETACH, params.pid, 0, ptrace_ctx.stop_info.si_signo);
            }

            exit(0);
        }
    }

    return 0;
}


static waitres_t
do_wait(ptrace_context *ctx, bool blocked)
{
    int status, ret;
    do {
        ret = waitpid(ctx->pid, &status, blocked ? 0 : WNOHANG);

        if (ret == 0)
            return WR_NOTHING;

        if (ret == -1 && errno != EINTR)
            err(2, "waitpid failed");
    } while(ret < 0);

    assert(ret == ctx->pid) ;
    assert(!WIFCONTINUED(status));

    if (WIFEXITED(status)) {
        print_message("Traced process (%d) exited with code %d", ctx->pid, WEXITSTATUS(status));
        return WR_FINISHED;
    }
    if (WIFSIGNALED(status)) {
        print_message("Traced process (%d) terminated by signal %d (%s)", ctx->pid, 
            WTERMSIG(status), strsignal(WTERMSIG(status)));
        return WR_FINISHED;
    }

    assert(WIFSTOPPED(status));

    if (ptrace(PTRACE_GETSIGINFO, ctx->pid, 0, &ctx->stop_info) < 0) {
        warn("PTRACE_GETSIGINFO failed");
        return WR_STOPPED; /* definitely group-stop */
    }

    /* The difference is "who stopped the process". This may be any signal sent to process (1)
     * or its SIGSTOP (2) sent by us, or SIGSTOP or SIGTSTP (^Z) sent by other prcesses(3)
     */
    if (WSTOPSIG(status) == SIGSTOP) {
        if (ctx->stop_info.si_pid == getpid())
            return WR_STOPPED; /* [2] */
    }
    
    /* [3] */
    if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP || 
        WSTOPSIG(status) == SIGTTIN || WSTOPSIG(status) == SIGTTOU) {
        return WR_DETACHED;
    }

    return WR_STOPPED; /* [1] */
}


static waitres_t
discard_wait(ptrace_context *ctx)
{
    for(;;) {
        waitres_t wres = do_wait(ctx, false);

        switch (wres) {
            case WR_NOTHING:
            case WR_FINISHED:
            case WR_DETACHED:
                return wres;

            case WR_STOPPED:
                if (ctx->stop_info.si_pid == getpid())
                    ptrace(PTRACE_CONT, ctx->pid, 0, 0);
                else {
                    print_message("Reflecting signal %d (%s)", ctx->stop_info.si_signo, strsignal(ctx->stop_info.si_signo));
                    ptrace(PTRACE_CONT, ctx->pid, 0, ctx->stop_info.si_signo);
                }
                break;
        }
    }
}


static bool
parse_args(program_params *params, int argc, char **argv)
{
    while(1) {
        int c;
        enum { PRINT_FULL_STACK = 256, JUST_PRINT_SYMBOLS };

        static struct option long_opts[] = {
            {"help",          no_argument,       0,  'h' },
            {"freq",          required_argument, 0,  'f' },
            {"full-stack",    no_argument,       0,   PRINT_FULL_STACK   },
            {"print-symbols", no_argument,       0,   JUST_PRINT_SYMBOLS },
            {"max-depth",     required_argument, 0,  'm' },
            {"realtime",      no_argument,       0,  'r' },
            {"min-cost",      required_argument, 0,  'c' },
            {"dump",          required_argument, 0,  'd' }
        };

        c = getopt_long(argc, argv, "m:rc:d:f:h", long_opts, NULL);
        if (c == -1) {
            argc -= optind;
            argv += optind;
            break;
        }

        switch(c) {
            case 'c':
                params->vprops.min_cost = atoi(optarg);
                break;
            case 'd':
                params->dumpfile = optarg;
                break;
            case 'f':
                params->us_sleep = FREQ_2PERIOD_USEC(atoi(optarg));
                break;
            case 'm':
                params->vprops.max_depth = atoi(optarg);
                break;
            case 'r':
                params->prof_method = PROF_REALTIME;
                break;
            case PRINT_FULL_STACK:
                params->vprops.print_fullstack = true;
                break;
            case JUST_PRINT_SYMBOLS:
                params->just_print_symbols = true;
                break;
            default:
                usage();
        }
    }

    if (argc != 1) {
        usage();
    }

    params->pid = atoi(argv[0]);
    return true;
}


static void 
dump_profile(const std::vector<fn_descr> &funcs, calltree_node *root, 
             const char *filename)
{
    std::ofstream of(filename);
    dump_callgrind(funcs, root, of); 
    print_message("Profile saved to %s (Callgrind format)", filename);
}

// Select shortest name if any aliases
struct fdescr_comparator
{
    bool operator()(const fn_descr &a, const fn_descr &b) const {
        return (a.addr == b.addr) ? 
                ( (a.len == b.len) ? strlen(a.name) < strlen(b.name) : a.len < b.len )
               : a.addr < b.addr;
    }
};


struct fdescr_addr_cmp
{
    bool operator()(const fn_descr &a, const fn_descr &b) const {
        return (a.addr == b.addr);
    }
};

static void 
read_symbols(pid_t pid, std::vector<fn_descr> *funcs)
{
    struct maps_ctx *mctx;
    struct maps_info *minf;
    char *exe;

    exe = proc_get_exefilename(pid);
    if (!exe)
        err(1, "Failed to get path of %d", pid);

    elfreader_init();
    mctx = maps_fopen(pid);
    if (!mctx)
        err(1, "Failed to open maps file of PID %d", int(pid));
    
    while ((minf = maps_readnext(mctx)) != NULL) {
        if ((minf->prot & PROT_EXEC) && minf->pathname[0] == '/') {
            elf_reader_t *er;

            if (!strcmp(minf->pathname, exe)) {
                print_message("reading symbols from %s (exe)", minf->pathname);
                // [1] read text table
                er = elf_read_textf(minf->pathname);

                if (!er)
                    err(1, "Failed to read text data from %s", minf->pathname);

                for (int i = 0; i < er->nsymbols; i++) {
                    const elf_symbol_t &es = er->symbols[i];
                    if (es.symbol_class == 'T') {
                        fn_descr descr;

                        descr.name = strdup(cplus_demangle(es.symbol_name, AUTO_DEMANGLING) ?: es.symbol_name);
                        descr.addr = (long)es.symbol_value;
                        descr.len  = es.symbol_size;

                        funcs->push_back(descr);
                    }
                }
                elfreader_close(er);
            }
            else {
                // [2] read dynamic table
                off_t load_offset = minf->offset;
                off_t load_end = minf->offset + ((char *)minf->end_addr - (char *)minf->start_addr);
                er = elf_read_dynaf(minf->pathname);

                print_message("reading symbols from %s (dynlib)", minf->pathname);

                if (!er)
                    err(1, "Failed to read dynamic data from %s", minf->pathname);

                for (int i = 0; i < er->nsymbols; i++) {
                    const elf_symbol &es = er->symbols[i];
                    if ((es.symbol_class == 'T' || es.symbol_class == 'W') && 
                        (off_t)es.symbol_value >= load_offset && (off_t)es.symbol_value < load_end) 
                    {
                        fn_descr descr;

                        descr.name = strdup(cplus_demangle(es.symbol_name, AUTO_DEMANGLING) ?: es.symbol_name);
                        descr.addr = (long)((off_t)es.symbol_value - load_offset + (char *)minf->start_addr);
                        descr.len  = es.symbol_size;

                        funcs->push_back(descr);
                    }
                }
                elfreader_close(er);
            }
        }
        maps_free(minf);
    }

    maps_close(mctx);

    // remove duplicates/overlapped functions
    std::sort(funcs->begin(), funcs->end(), fdescr_comparator());
    std::vector<fn_descr>::iterator it = std::unique(funcs->begin(), funcs->end(), fdescr_addr_cmp());
    funcs->erase(it, funcs->end());

}

static void
print_symbols(const std::vector<fn_descr> &fns)
{
    for(std::vector<fn_descr>::const_iterator it = fns.begin(); it != fns.end(); ++it) {
        printf("%p\t%d\t%s\n", (void *)it->addr, it->len, it->name);
    }
}

static void 
usage()
{
    fprintf(stderr, "Usage: %s [-m|--max-depth N] [-h] pid\n", g_progname);
    fprintf(stderr, "\t-h|--help: show this help\n"
                    "\t-m|--max-depth N: unwind no more than N frames\n\n");
    exit(EX_USAGE);
}
