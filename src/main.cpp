#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

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
bool sigint_caught = false;
bool sigint_caught_twice = false;

static char *g_progname;

void on_sigint(int)
{
    struct timeval tv, tv_diff;
    gettimeofday(&tv, NULL);

    sigint_caught  = true;
   
    timersub(&tv, &tv_last_sigint, &tv_diff);
    if (!tv_diff.tv_sec && tv_diff.tv_usec < 333000)
        sigint_caught_twice = true;

    tv_last_sigint = tv;
}

void on_sigalarm(int)
{
    /* nothing, just break sleep() */
}


static void dump_profile(const std::vector<fn_descr> &funcs, calltree_node *root, const char *filename);
static void read_symbols(pid_t pid, std::vector<fn_descr> *funcs);
static void usage();

#define FREQ_2PERIOD_USEC(n) ( 1000000 / (n) )

struct program_params
{
    unsigned us_sleep;
    int pid;
    vproperties vprops;
    const char *dumpfile;
    crxprof_method prof_method;

    program_params() : us_sleep(FREQ_2PERIOD_USEC(DEFAULT_FREQ)), 
                       dumpfile(NULL), prof_method(PROF_CPUTIME) {}
};

static bool parse_args(program_params *params, int argc, char **argv);

int main(int argc, char *argv[])
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

    calltree_node *root = NULL;

    print_message("Attaching to process: %d", params.pid);
    ptrace_ctx.stopped = false;
    attach_process(params.pid, &ptrace_ctx);

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
        unsigned n = params.prof_method == PROF_REALTIME ? 1 : get_cpudiff_us(&ptrace_ctx);
        char st = get_procstate(ptrace_ctx);
        if (st != 'S')
            fill_backtrace(n, &ptrace_ctx, funcs, &root);

        sleep(1);

        if (sigint_caught_twice) {
            print_message("Exit");
            exit(0);
        }

        if (sigint_caught) {
            if (root) {
                visualize_profile(root, params.vprops);
                if (params.dumpfile)
                    dump_profile(funcs, root, params.dumpfile);
            } else
                print_message("No symbolic snapshot caught yet!");


            sigint_caught = false;
            root = NULL; // TODO: clear 
        }
    }

    return 0;
}


static bool
parse_args(program_params *params, int argc, char **argv)
{
    while(1) {
        int c;
        enum { PRINT_FULL_STACK = 257 };

        static struct option long_opts[] = {
            {"help",         no_argument,       0,  'h' },
            {"freq",         required_argument, 0,  'f' },
            {"full-stack",   no_argument,       0,   PRINT_FULL_STACK },
            {"max-depth",    required_argument, 0,  'm' },
            {"realtime",     no_argument,       0,  'r' },
            {"min-cost",     required_argument, 0,  'c' },
            {"dump",         required_argument, 0,  'd' }
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

    elfreader_init();
    mctx = maps_fopen(pid);
    if (!mctx)
        err(1, "Failed to open maps file of PID %d", int(pid));
    
    while ((minf = maps_readnext(mctx)) != NULL) {
        if ((minf->prot & PROT_EXEC) && minf->pathname[0] == '/') {
            print_message("reading symbols from %s", minf->pathname);
            elf_reader_t *er;

            // [1] read text table
            er = elf_read_textf(minf->pathname);

            if (!er)
                err(1, "Failed to read text data from %s", minf->pathname);

            for (int i = 0; i < er->nsymbols; i++) {
                const elf_symbol_t &es = er->symbols[i];
                if (es.symbol_class == 'T') {
                    fn_descr descr;

                    descr.name = strdup(es.symbol_name);
                    descr.addr = (long)es.symbol_value;
                    descr.len  = es.symbol_size;

                    funcs->push_back(descr);
                }
            }
            elfreader_close(er);


            // [2] read dynamic table
            off_t load_offset = minf->offset;
            off_t load_end = minf->offset + ((char *)minf->end_addr - (char *)minf->start_addr);
            er = elf_read_dynaf(minf->pathname);

            if (!er)
                err(1, "Failed to read dynamic data from %s", minf->pathname);

            for (int i = 0; i < er->nsymbols; i++) {
                const elf_symbol &es = er->symbols[i];
                if ((es.symbol_class == 'T' || es.symbol_class == 'W') && 
                    (off_t)es.symbol_value >= load_offset && (off_t)es.symbol_value < load_end) 
                {
                    fn_descr descr;

                    descr.name = strdup(es.symbol_name);
                    descr.addr = (long)((off_t)es.symbol_value - load_offset + (char *)minf->start_addr);
                    descr.len  = es.symbol_size;

                    funcs->push_back(descr);
                }
            }
            elfreader_close(er);
        }
        maps_free(minf);
    }

    maps_close(mctx);

    // remove duplicates/overlapped functions
    std::sort(funcs->begin(), funcs->end(), fdescr_comparator());
    std::vector<fn_descr>::iterator it = std::unique(funcs->begin(), funcs->end(), fdescr_addr_cmp());
    funcs->erase(it, funcs->end());

    /*for(std::vector<fn_descr>::iterator it = funcs->begin(); it != funcs->end(); it++) {
        printf("%p\t%d\t%s\n", it->addr, it->len, it->name);
    }*/
}

static void usage()
{
    fprintf(stderr, "Usage: %s [-m|--max-depth N] [-h] pid\n", g_progname);
    fprintf(stderr, "\t-h|--help: show this help\n"
                    "\t-m|--max-depth N: unwind no more than N frames\n\n");
    exit(EX_USAGE);
}
