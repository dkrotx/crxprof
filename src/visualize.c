#include <stdlib.h>
#include "crxprof.h"

static int
nodes_weight_cmp(const calltree_node *a, const calltree_node *b)
{
    uint64_t acost = (a->nintermediate + a->nself),
             bcost = (b->nintermediate + b->nself);

    return (bcost == acost) ? 0 : 
         ( (bcost  > acost) ? 1 : -1 );
}

static uint64_t
count_calls(calltree_node *node) {
    uint64_t n = node->nself, i;

    for (i = 0; i < node->nchilds; i++) {
        n += count_calls(&node->childs[i]);
    }

    return n;
}

static void
show_layer(const vproperties *vprops, 
           calltree_node *node, 
           uint64_t total_cost, 
           int depth,
           bool is_last)
{
  double percent_full = (double)(node->nintermediate + node->nself) * 100.0 / total_cost;
  int i;
  
  if (percent_full >= vprops->min_cost) {
      if (depth > 0) {
        if (depth == 1) {
          printf(" \\_ ");
        } else {
          printf(is_last ? "   " : " | ");
          for(i = 0; i < depth - 2; i++)
            printf("  ");

          printf("\\_ ");
        }
      }

      double percent_self = (double)node->nself * 100.0 / total_cost;
      
      printf("%.60s (%.1f%% | %.1f%% self)\n", node->pfn->name, percent_full, percent_self);
      if (node->nchilds) {
          qsort(node->childs, node->nchilds, 
                sizeof(calltree_node),
                (qsort_compar_t)nodes_weight_cmp);

          for (i = 0; i < node->nchilds; i++) {
              show_layer(vprops, &node->childs[i], total_cost, 
                         depth + 1, is_last || (depth == 1 && i == node->nchilds-1));
          }
      }
  }
}


void
visualize_profile(calltree_node *root, const vproperties *vprops)
{
    uint64_t total_cost = count_calls(root);

    if (total_cost) {
        calltree_node *start = root;
       
        /* skip uninsterested start-functions */
        if (!vprops->print_fullstack) {
            while (!start->nself && start->nchilds == 1)
                start = &start->childs[0];
        }
        show_layer(vprops, start, total_cost, 0, false);
    }
}
