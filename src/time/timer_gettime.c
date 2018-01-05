#include <time.h>
#include <limits.h>
#include "syscall.h"

int timer_gettime(timer_t t, struct itimerspec *val)
{
	return syscall(SYS_timer_gettime, t, val);
}
