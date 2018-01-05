#include <time.h>
#include <limits.h>
#include "pthread_impl.h"

int timer_settime(timer_t t, int flags, const struct itimerspec *restrict val, struct itimerspec *restrict old)
{
	return syscall(SYS_timer_settime, t, flags, val, old);
}
