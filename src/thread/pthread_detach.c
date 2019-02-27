#include "pthread_impl.h"
#include <threads.h>

static int __pthread_detach(pthread_t t)
{
	lthread_detach2(t);
	return 0;
}

weak_alias(__pthread_detach, pthread_detach);
weak_alias(__pthread_detach, thrd_detach);
