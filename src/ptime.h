#ifndef CRXPROF_PTIME_H_
#define CRXPROF_PTIME_H_

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "../config.h"


typedef enum { PROF_REALTIME = 1, PROF_CPUTIME = 2, PROF_IOWAIT = 4 } crxprof_method;

struct proc_timer
{
    uint64_t prev_time;
    clockid_t clock_id;
};


bool reset_process_time(struct proc_timer *pt, pid_t pid, crxprof_method method, int *error);
uint64_t get_process_dt(struct proc_timer *pt);

#endif /* CRXPROF_PTIME_H_ */
