#ifndef CRXPROF_H__
#define CRXPROF_H__

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


typedef struct {
    unw_word_t ips[MAX_STACK_DEPTH];
    int depth;
} trace_stack ;

typedef struct {
    pid_t pid;
    unw_addr_space_t addr_space;
    void *unwind_rctx;
    int stop_signal;

    char procstat_path[sizeof("/proc/4000000000/stat")];
    char *cmdline;
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
char get_procstate(const ptrace_context *ctx); /* One character from the string "RSDZTW" */

/* visualize and dumps */
void visualize_profile(calltree_node *root, const vproperties *vprops);
void dump_callgrind(const ptrace_context *ctx, calltree_node *root, FILE *ofile);


void print_message(const char *fmt, ...) __attribute__((__format__(printf, 1, 2)));
void wait4keypress(bool *key_pressed);


#endif /* CRXPROF_H_*/
