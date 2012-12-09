#ifndef CRXPROF_DEFS_HPP__
#define CRXPROF_DEFS_HPP__

// '!!' are here to ensure that __builtin_expect's first param is either 1 or 0
#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)

#define __PACKED __attribute__((__packed__))

#endif /* CRXPROF_DEFS_HPP__ */
