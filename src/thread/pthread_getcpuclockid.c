#include "pthread_impl.h"

int pthread_getcpuclockid(pthread_t t, clockid_t *clockid)
{
	/*
	 * [PRP HACK] Workaround for .Net CoreCLR
	 *
	 * In SGX-LKL, the lthread scheduler currently does not track per-thread CPU
	 * time, and thus cannot return a per-thread CPU clock. Instead, we are
	 * returning the default real-time clock. This should not break application
	 * functionality.
	 *
	 * The line below used to be:
	 *
	 * *clockid = (-t->tid-1)*8U + 6;
	 */

	*clockid = CLOCK_REALTIME;
	return 0;
}
