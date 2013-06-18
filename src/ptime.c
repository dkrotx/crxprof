/**
 * ptime.h
 * get process CPU time
 */
#include <errno.h>
#include "ptime.h"

static uint64_t
get_process_time(const struct proc_timer *pt) {
    struct timespec ts;

    return (clock_gettime(pt->clock_id, &ts) == -1) ?
        -1 :
        (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}


bool
reset_process_time(struct proc_timer *pt, pid_t pid, crxprof_method method, int *error) {
    switch(method) {
        case PROF_REALTIME:
            pt->clock_id = CLOCK_MONOTONIC;
            break;
        case PROF_CPUTIME:
            /* clock_getcpuclockid uses rc instead of `errno' */
            if ( (*error = clock_getcpuclockid(pid, &pt->clock_id)) != 0)
                return false;
            break;
        case PROF_IOWAIT:
            return false; /* unsupported */
            break;
    }

    pt->prev_time = get_process_time(pt);
    *error = errno;
    return pt->prev_time != (uint64_t)-1;
}


uint64_t
get_process_dt(struct proc_timer *pt) {
    uint64_t t = get_process_time(pt);
    uint64_t dt = t - pt->prev_time;

    pt->prev_time = t;
    return dt;
}
