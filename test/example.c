/* demo file for crxprof
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/* This function should be seen only with -r (realtime) option
 */
void sleeping_fn(int us) {
    usleep(us);
}

#define CALC_NOTHING(how_much) do {            \
    int i, j, sum = 0;                         \
    for (i = 0; i < (how_much) * 40000; i++)   \
        for (j = 1; j < 1000; j++)             \
            sum += ( i * j ) | ( i / j );      \
    } while(0)

void fn() {
    CALC_NOTHING(1);
    sleeping_fn(80000);
}

void heavy_fn() {
    CALC_NOTHING(2);
    fn();
}


int main()
{
    printf("PID: %d\n", (int)getpid());

    for(;;) {
        heavy_fn();
        fn();
        printf("One more cycle\n");
    }

    return 0;
}
