/**
 * main.c
 * Entry point of crxprof. Parse arguments and collect symbols of given process (ID).
 */

#define __STDC_FORMAT_MACROS

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sysexits.h>
#include <getopt.h>
#include <err.h>

#include "crxprof.h"
#include "ptime.h"


static volatile bool sigint_caught = false;
static volatile bool timer_alarmed = false;

static char *g_progname;

void
on_sigint(int sig) {
    sigint_caught  = true;
}

void
on_sigalarm(int sig) {
    timer_alarmed = true;
}

void
on_sigchld(int sig) {
    /* just for hang up */
}


#define FREQ_2PERIOD_USEC(n) ( 1000000 / (n) )

typedef struct 
{
    unsigned us_sleep;
    int pid;
    vproperties vprops;
    const char *dumpfile;
    crxprof_method prof_method;
    bool just_print_symbols;
} program_params;



typedef enum { WR_NOTHING, WR_FINISHED, WR_NEED_DETACH, WR_STOPPED } waitres_t;
static waitres_t do_wait(ptrace_context *ctx, bool blocked);
static waitres_t discard_wait(ptrace_context *ctx);
static void set_sigalrm();

static void dump_profile(calltree_node *root, const char *filename);
static void print_symbols();
static bool parse_args(program_params *params, int argc, char **argv);
static long ptrace_verbose(enum __ptrace_request request, pid_t pid,
                   void *addr, intptr_t data);
static void usage();


int
main(int argc, char *argv[])
{
    bool need_exit = false;
    ptrace_context ptrace_ctx;
    program_params params;
    struct itimerval itv;
    struct proc_timer proc_time;
    calltree_node *root = NULL;

    g_progname = argv[0];
    if (!parse_args(&params, argc, argv))
        usage();

    print_message("Reading symbols (list of function)");
    init_fndescr(params.pid);
    if (params.just_print_symbols) {
        print_symbols();
        free_fndescr();
        exit(0);
    }


    if (!reset_process_time(&proc_time, params.pid, params.prof_method)) {
        free_fndescr();
        errx(2, "Failed to retrieve process time");
    }


    print_message("Attaching to process: %d", params.pid);
    memset(&ptrace_ctx, 0, sizeof(ptrace_ctx));
    if (!trace_init(params.pid, &ptrace_ctx))
        err(1, "Failed to initialize unwind internals");

    signal(SIGCHLD, on_sigchld);
    if (ptrace(PTRACE_ATTACH, params.pid, 0, 0) == -1) {
        int saved_errno = errno;
        warn("ptrace(PTRACE_ATTACH) failed");
        if (saved_errno == EPERM) {
            printf("You have to see NOTES section of `man crxprof' for workarounds.\n");
        }
        exit(2);
    }

    if (do_wait(&ptrace_ctx, true) != WR_STOPPED)
        err(1, "Error occured while stopping the process");

    if (ptrace(PTRACE_CONT, params.pid, 0, 0) < 0)
        err(1, "Error occured while stopping the process 2");


    /* interval timer for snapshots */
    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = params.us_sleep;
    itv.it_value = itv.it_interval;

    set_sigalrm();
    if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
        err(1, "setitimer failed");

    print_message("Starting profile (interval %dms)", params.us_sleep / 1000);
    print_message("Press ENTER to show profile, ^C to quit");
    signal(SIGINT, on_sigint);

    /* drop first meter since it contains our preparations */
    (void)get_process_dt(&proc_time); 

    while(!need_exit)
    {
        waitres_t wres = WR_NOTHING;
        bool key_pressed = false;

        wait4keypress(&key_pressed);

        if (timer_alarmed) {
            uint64_t proc_dt = get_process_dt(&proc_time);
            bool need_prof = (params.prof_method == PROF_REALTIME);

            if (params.prof_method == PROF_CPUTIME) {
                char st = get_procstate(&ptrace_ctx);
                if (st == 'R')
                    need_prof = true;
            }

            if (need_prof) {
                kill(params.pid, SIGSTOP);
                wres = do_wait(&ptrace_ctx, true);
                if (wres == WR_STOPPED) {
                    int signo_cont = (ptrace_ctx.stop_signal == SIGSTOP) ? 0 : ptrace_ctx.stop_signal;

                    if (!get_backtrace(&ptrace_ctx))
                        err(2, "failed to get backtrace of process");

                    /* continue tracee ASAP */
                    if (ptrace_verbose(PTRACE_CONT, params.pid, 0, signo_cont) < 0)
                        err(1, "ptrace(PTRACE_CONT) failed");

                    ptrace_ctx.nsnaps++;
                    if (fill_backtrace(proc_dt, &ptrace_ctx.stk, &root))
                        ptrace_ctx.nsnaps_accounted++;
                }
            }

            timer_alarmed = 0;
        }

        if (wres != WR_FINISHED && wres != WR_NEED_DETACH) {
            wres = discard_wait(&ptrace_ctx);
        }

        if (sigint_caught) {
            print_message("Exit since ^C pressed");
            need_exit = true;
        }
        else if (key_pressed || wres == WR_FINISHED || wres == WR_NEED_DETACH) {
            if (root) {
                print_message("%" PRIu64 " snapshot interrputs got (%" PRIu64 " dropped)", 
                    ptrace_ctx.nsnaps, ptrace_ctx.nsnaps - ptrace_ctx.nsnaps_accounted);

                visualize_profile(root, &params.vprops);
                if (params.dumpfile)
                    dump_profile(root, params.dumpfile);
            } else
                print_message("No symbolic snapshot caught yet!");
        }

        if (wres == WR_FINISHED || wres == WR_NEED_DETACH) {
            if (wres == WR_NEED_DETACH) {
                (void)ptrace_verbose(PTRACE_DETACH, params.pid, 0, ptrace_ctx.stop_signal);
                print_message("Exit since program is stopped by (%d=%s)", ptrace_ctx.stop_signal, strsignal(ptrace_ctx.stop_signal));
            }
            else
                print_message("Exit since traced program is finished");

            need_exit = true;
        }
    }

    free_fndescr();
    trace_free(&ptrace_ctx);
    if (root)
        calltree_destroy(root);

    return 0;
}


static void
set_sigalrm()
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigalarm;
    sa.sa_flags   = SA_RESTART;

    if (sigaction(SIGALRM, &sa, NULL) == -1)
        err(1, "sigaction SIGALRM failed");
}


static long 
ptrace_verbose(enum __ptrace_request request, pid_t pid,
               void *addr, intptr_t data)
{
    if ((request == PTRACE_CONT || request == PTRACE_DETACH) && data != 0)
        print_message("Reflecting signal %d (%s)", (int)data, strsignal(data));

    if (request == PTRACE_DETACH)
        print_message("Detach from process #%d", (int)pid);

    return ptrace(request, pid, addr, data);
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
    ctx->stop_signal = WSTOPSIG(status);

    if (ctx->stop_signal == SIGTSTP || 
        ctx->stop_signal == SIGTTIN || ctx->stop_signal == SIGTTOU) {
        return WR_NEED_DETACH;
    }
        
    return WR_STOPPED;
}


static waitres_t
discard_wait(ptrace_context *ctx)
{
    for(;;) {
        waitres_t wres = do_wait(ctx, false);

        switch (wres) {
            case WR_NOTHING:
            case WR_FINISHED:
            case WR_NEED_DETACH:
                return wres;

            case WR_STOPPED:
                ptrace_verbose(PTRACE_CONT, ctx->pid, 0, 
                    ctx->stop_signal == SIGSTOP ? 0 : ctx->stop_signal);
                break;
        }
    }
}


static bool
parse_args(program_params *params, int argc, char **argv)
{
    params->us_sleep = FREQ_2PERIOD_USEC(DEFAULT_FREQ);
    params->dumpfile = NULL;
    params->prof_method = PROF_CPUTIME;
    params->just_print_symbols = false;

    params->vprops.max_depth = -1U;
    params->vprops.min_cost  = DEFAULT_MINCOST;
    params->vprops.print_fullstack = false;


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
            {"threshold",     required_argument, 0,  't' },
            {"dump",          required_argument, 0,  'd' }
        };

        c = getopt_long(argc, argv, "m:rt:d:f:h", long_opts, NULL);
        if (c == -1) {
            argc -= optind;
            argv += optind;
            break;
        }

        switch(c) {
            case 't':
                params->vprops.min_cost = atof(optarg);
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
dump_profile(calltree_node *root, const char *filename)
{
    FILE *ofile;

    ofile = fopen(filename, "w");
    if (!ofile)
        err(1, "Failed to open file %s", filename);

    dump_callgrind(root, ofile); 
    print_message("Profile saved to %s (Callgrind format)", filename);
}


static void
print_symbols() {
    int i;
    for(i = 0; i < g_nfndescr; i++) {
        printf("%p\t%d\t%s\n", (void *)g_fndescr[i].addr, 
               g_fndescr[i].len, g_fndescr[i].name);
    }
}

static void 
usage()
{
    fprintf(stderr, "Usage: %s [options] pid\n", g_progname);
    fprintf(stderr, "Options are:\n");
    fprintf(stderr, "\t-t|--threshold N:  visualize nodes that takes at least N%% of time (default: %.1f)\n", DEFAULT_MINCOST);
    fprintf(stderr, "\t-d|--dump FILE:    save callgrind dump to given FILE\n");
    fprintf(stderr, "\t-f|--freq FREQ:    set profile frequency to FREQ Hz (default: %d)\n", DEFAULT_FREQ);
    fprintf(stderr, "\t-m|--max-depth N:  show at most N levels while visualizing (default: no limit)\n");
    fprintf(stderr, "\t-r|--realtime:     use realtime profile instead of CPU\n");
    fprintf(stderr, "\t-h|--help:         show this help\n\n");

    fprintf(stderr, "\t--full-stack:      print full stack while visualizing (see manual)\n");
    fprintf(stderr, "\t--print-symbols:   just print funcs and addrs (and quit)\n\n");
    exit(EX_USAGE);
}
