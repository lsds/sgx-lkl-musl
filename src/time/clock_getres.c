#include <time.h>
#include "syscall.h"

/*
  CLOCK_REALTIME (1) to CLOCK_BOOTTIME (7)
*/
#define CLOCK_RES_MAX CLOCK_BOOTTIME
struct timespec host_clock_res[CLOCK_RES_MAX + 1];

void init_clock_res(struct timespec clock_res[]) {
	for (int i = 0; i <= CLOCK_RES_MAX; i++) {
		host_clock_res[i] = clock_res[i];
	}
}

int clock_getres(clockid_t clk, struct timespec *ts)
{
	/* Unsupported for now */
	if (clk == CLOCK_PROCESS_CPUTIME_ID ||
	    clk == CLOCK_THREAD_CPUTIME_ID)
		return -1;

	if (clk <= CLOCK_RES_MAX) {
		*ts = host_clock_res[clk];
		return 0;
	}
	return syscall(SYS_clock_getres, clk, ts);
}
