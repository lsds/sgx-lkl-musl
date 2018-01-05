#include "pthread_impl.h"

int pthread_kill(pthread_t t, int sig)
{
        lthread_cancel(t);
	return 0;
}
