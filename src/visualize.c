#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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


static inline double
get_node_cost(const calltree_node *node, uint64_t total_cost)
{
  return (double)(node->nintermediate + node->nself) * 100.0 / total_cost;
}

#define VIS_PADDING 4

typedef struct visualize_info_struct {
    const vproperties *vprops;
    uint64_t           total_cost;
    char               prefix[512];
} visualize_info;


static int
count_visible_childs(const calltree_node *node,
                     uint64_t total_cost, double min_cost)
{
    int i;

    for(i = 0; i < node->nchilds; i++) {
        if (get_node_cost(&node->childs[i], total_cost) < min_cost)
            break;
    }

    return i;
}


static void
show_layer(visualize_info *vi,
           calltree_node *node, 
           int depth,
           bool is_last)
{
    double percent_full = get_node_cost(node, vi->total_cost);
    double percent_self = (double)node->nself * 100.0 / vi->total_cost;

    if (depth > 0) {
        printf("%.*s", (depth-1) * VIS_PADDING, vi->prefix);
        printf(" \\_ ");
    }

    printf("%.60s (%.1f%% | %.1f%% self)\n", node->pfn->name, percent_full, percent_self);
    if (node->nchilds) {
        qsort(node->childs, node->nchilds,
              sizeof(calltree_node),
              (qsort_compar_t)nodes_weight_cmp);

        if (depth > 0)
            memcpy(&vi->prefix[(depth-1)*VIS_PADDING], is_last ? "    " : " |  ", VIS_PADDING);

        int nvis = count_visible_childs(node, vi->total_cost, vi->vprops->min_cost), i;
        for (i = 0; i < nvis; i++) {
            show_layer(vi, &node->childs[i], depth + 1, i+1 == nvis);
        }
    }
}


void
visualize_profile(calltree_node *root, const vproperties *vprops)
{
    uint64_t total_cost = count_calls(root);

    if (total_cost) {
        calltree_node *start = root;
        visualize_info vi;

        vi.vprops = vprops;
        vi.total_cost = total_cost;
       
        /* skip uninsterested start-functions */
        if (!vprops->print_fullstack) {
            while (!start->nself && start->nchilds == 1)
                start = &start->childs[0];
        }

        show_layer(&vi, start, 0, false);
    }
}
