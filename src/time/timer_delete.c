#include <time.h>
#include <limits.h>
#include "pthread_impl.h"

int timer_delete(timer_t t)
{
	return __syscall(SYS_timer_delete, t);
}
