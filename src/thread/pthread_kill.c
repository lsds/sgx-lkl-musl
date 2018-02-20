#include "pthread_impl.h"
#include "signal.h"

int pthread_kill(pthread_t t, int sig)
{
	if(sig == SIGTERM || sig == SIGKILL) {
		lthread_cancel(t);
	}
	return 0;
}
