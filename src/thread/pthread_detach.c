#include "pthread_impl.h"

int __pthread_join(pthread_t, void **);

static int __pthread_detach(pthread_t t)
{
	lthread_detach2(t);
	return 0;
}

weak_alias(__pthread_detach, pthread_detach);
