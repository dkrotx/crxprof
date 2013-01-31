#include <stdio.h>
#include <algorithm>

#include "crxprof.hpp"

struct nodes_weight_cmp
{
    bool operator()(calltree_node *a, calltree_node *b) const {
        return (b->nintermediate + b->nself) < (a->nintermediate + a->nself);
    }
};

static uint64_t count_calls(const calltree_node *node)
{
    uint64_t n = node->nself;

    for (siblings_t::const_iterator it = node->childs.begin(); 
         it != node->childs.end(); it++) {
        n += count_calls(*it);
    }

    return n;
}

static void show_layer(const vproperties &vprops, calltree_node *node, 
                       uint64_t total_cost, int depth = 0, bool is_last = false)
{
  double percent_full = (double)(node->nintermediate + node->nself) * 100.0 / total_cost;
  
  if (percent_full >= vprops.min_cost) 
  {
      if (depth > 0) {
        if (depth == 1) {
          printf(" \\_ ");
        } else {
          printf(is_last ? "   " : " | ");
          for(int i = 0; i < depth - 2; i++)
            printf("  ");

          printf("\\_ ");
        }
      }

      double percent_self = (double)node->nself * 100.0 / total_cost;
      
      printf("%.60s (%.1f%% | %.1f%% self)\n", node->pfn->name, percent_full, percent_self);
      std::sort(node->childs.begin(), node->childs.end(), nodes_weight_cmp());

      int n = node->childs.size();
      for (int i = 0; i < n; i++) {
          show_layer(vprops, node->childs[i], total_cost, 
                     depth + 1, is_last || (depth == 1 && i == n-1));
      }
  }
}


void visualize_profile(calltree_node *root, const vproperties &vprops)
{
    uint64_t total_cost = count_calls(root);

    if (total_cost) {
        calltree_node *start = root;
        
        if (!vprops.print_fullstack) {
            while (!start->nself && start->childs.size() == 1)
                start = start->childs[0];
        }
        show_layer(vprops, start, total_cost);
    }
}
