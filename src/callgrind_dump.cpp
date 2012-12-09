/*
 *  Dump calltree in Callgrind format (http://valgrind.org/docs/manual/cl-format.html)
 */

#include "crxprof.hpp"
#include <stdint.h>
#include <algorithm>



struct call_summary {
  std::vector<int> fn_ids;
  const fn_descr *first_fn_descr;
  uint64_t total_cost;
  
  call_summary(const std::vector<fn_descr> &funcs) : first_fn_descr(&funcs[0]), total_cost(0U) {}
};

static void collect_summary_bynodes(calltree_node *node, call_summary &ctx) {
  ctx.fn_ids.push_back(node->pfn - ctx.first_fn_descr);
  ctx.total_cost += node->nself;
  
  for (siblings_t::const_iterator it = node->childs.begin(); it != node->childs.end(); ++it)
    collect_summary_bynodes(*it, ctx); 
}

static void collect_summary(calltree_node *root, call_summary &summary)
{
  collect_summary_bynodes(root, summary);
  
  std::sort(summary.fn_ids.begin(), summary.fn_ids.end());
  std::vector<int>::iterator it = std::unique(summary.fn_ids.begin(), summary.fn_ids.end());
  summary.fn_ids.resize(it - summary.fn_ids.begin());
}

static void
print_costs(const call_summary &summary, calltree_node *node, std::ostream &os)
{
    os << "fn=(" << node->pfn - summary.first_fn_descr << ")\n";
    os << "1 " << node->nself << "\n";

    for (siblings_t::const_iterator it = node->childs.begin(); it != node->childs.end(); ++it) {
        calltree_node *child = *it;
        os << "cfn=(" << child->pfn - summary.first_fn_descr << ")\n";
        os << "calls=" << child->nself + child->nintermediate << " 1\n" ;
        os << "1 " << child->nself + child->nintermediate << "\n";
    }

    for (siblings_t::const_iterator it = node->childs.begin(); it != node->childs.end(); ++it) {
        os << "\n";
        print_costs(summary, *it, os);
    }
}


void dump_callgrind(const std::vector<fn_descr> &funcs, calltree_node *root, std::ostream &os)
{ 
  call_summary summary(funcs);
  
  collect_summary(root, summary);
  os << "events: Instructions\n";
  os << "summary: " << 	summary.total_cost << "\n";
  
  os << "\n\n";
  for (std::vector<int>::const_iterator it = summary.fn_ids.begin(); it != summary.fn_ids.end(); ++it) {
    os << "fn=(" << *it << ") " << funcs[*it].name << "\n";
  }
    
  print_costs(summary, root, os);
  os << "\n\n";
}
