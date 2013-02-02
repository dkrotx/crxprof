#ifndef CRXPROF_H__
#define CRXPROF_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <libunwind.h>
#include <stdint.h>
#include <stdio.h>
#include "../config.h"

#define DEFAULT_MINCOST         5.0 /* % */
#define DEFAULT_FREQ            100
#define MAX_STACK_DEPTH         128

typedef struct {
    char         *name;
    unsigned long addr;
    unsigned int  len;
} fn_descr;


struct st_calltree_node;

typedef struct st_calltree_node {
    const fn_descr *pfn;
    uint64_t nintermediate;
    uint64_t nself;

    struct st_calltree_node *childs;
    int nchilds;
} calltree_node;


typedef enum { PROF_REALTIME = 1, PROF_CPUTIME = 2, PROF_IOWAIT = 4 } crxprof_method;

typedef struct {
    unw_word_t ips[MAX_STACK_DEPTH];
    int depth;
} trace_stack ;

typedef struct {
    pid_t pid;
    unw_addr_space_t addr_space;
    void *unwind_rctx;
    uint64_t prev_cputime;
    clockid_t clock_id;
    int stop_signal;

    char procstat_path[sizeof("/proc/4000000000/stat")];
    trace_stack stk;

    uint64_t nsnaps;
    uint64_t nsnaps_accounted;
} ptrace_context;

typedef struct {
    unsigned max_depth;
    double min_cost;
    bool print_fullstack;
} vproperties;


extern fn_descr *g_fndescr;
extern int g_nfndescr;

typedef int (*qsort_compar_t)(const void *, const void *);

/* fndescr-related functions */
void init_fndescr(pid_t pid);
void free_fndescr();

/* ptrace-related functions */
bool trace_init(pid_t pid, ptrace_context *ctx);
void trace_free(ptrace_context *ctx);
bool get_backtrace(ptrace_context *ctx);
bool fill_backtrace(uint64_t cost, const trace_stack *stk, 
                    calltree_node **root);
void calltree_destroy(calltree_node *root);
uint64_t get_cputime_ns(ptrace_context *ctx);
char get_procstate(const ptrace_context *ctx); /* One character from the string "RSDZTW" */

/* visualize and dumps */
void visualize_profile(calltree_node *root, const vproperties *vprops);
void dump_callgrind(calltree_node *root, FILE *ofile);


void print_message(const char *fmt, ...) __attribute__((__format__(printf, 1, 2)));

#endif /* CRXPROF_H_*/
