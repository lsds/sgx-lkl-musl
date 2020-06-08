#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <errno.h>
#include "pthread_impl.h"

#include "syscall.h"

int sched_setaffinity(pid_t tid, size_t size, const cpu_set_t *set)
{
        errno = ENOSYS;
        return -1;
}

int pthread_setaffinity_np(pthread_t td, size_t size, const cpu_set_t *set)
{
	// struct lthread *lt = (struct lthread *)td;
	// lt->attr.state |= BIT(LT_ST_PINNED);
	/* Don't call sched_setaffinity because ethreads are
	   already pinned to cores in the starter */
	return 0;
}

static int do_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
	CPU_ZERO_S(size, set);
	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	for (int i = 0; i < nproc; i++) {
		CPU_SET_S(i, size, set);
	}

	return 0;
}

int sched_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
	return __syscall_ret(do_getaffinity(tid, size, set));
}

int pthread_getaffinity_np(pthread_t td, size_t size, cpu_set_t *set)
{
	return -do_getaffinity(td->tid, size, set);
}
