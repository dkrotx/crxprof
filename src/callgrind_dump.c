/*
 * callgrind_dumpc.pp
 *
 *  Dump calltree in Callgrind format (http://valgrind.org/docs/manual/cl-format.html)
 */

#define __STDC_FORMAT_MACROS

#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include "crxprof.h"

static inline int
fn2id(const fn_descr *pfn) {
  assert(pfn >= g_fndescr);
  return pfn - g_fndescr;
}


typedef struct {
  char *fns_usemask;
  uint64_t total_cost;
} call_summary;

static void
collect_summary(calltree_node *node, call_summary *ctx) {
  int i;
  
  for (i=0; i < node->nchilds; i++) {
    collect_summary(&node->childs[i], ctx); 
  }
  
  ctx->fns_usemask[fn2id(node->pfn)] = 1;
  ctx->total_cost += node->nself;
}


static void
print_costs(const call_summary *summary, 
            const calltree_node *node, FILE *ofile)
{
    int i;

    fprintf(ofile, "fn=(%d)\n", fn2id(node->pfn));
    fprintf(ofile, "1 %" PRIu64 "\n", node->nself);

    for (i = 0; i < node->nchilds; i++) {
        const calltree_node *child = &node->childs[i];

        fprintf(ofile, "cfn=(%d)\n", fn2id(child->pfn));
        fprintf(ofile, "calls=%" PRIu64 " 1\n", child->nself + child->nintermediate);
        fprintf(ofile, "1 %" PRIu64 "\n", child->nself + child->nintermediate);
    }

    for (i = 0; i < node->nchilds; i++) {
        fprintf(ofile, "\n");
        print_costs(summary, &node->childs[i], ofile);
    }
}


void
dump_callgrind(calltree_node *root, FILE *ofile)
{
  int i;
  call_summary summary;
  summary.fns_usemask = calloc(1, g_nfndescr);
  assert(summary.fns_usemask);

  collect_summary(root, &summary);
  fprintf(ofile, "events: Instructions\n"
          "summary: %" PRIu64"\n\n\n", summary.total_cost);
  
  for (i = 0; i < g_nfndescr; i++) {
    if (summary.fns_usemask[i])
      fprintf(ofile, "fn=(%d) %s\n", i, g_fndescr[i].name);
  }
  free(summary.fns_usemask);

  print_costs(&summary, root, ofile);
  fprintf(ofile, "\n\n");
}
