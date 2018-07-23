#include "pthread_impl.h"
#include <threads.h>

int lthread_setspecific(pthread_key_t key, const void *value);

int tss_set(tss_t k, void *x)
{
	return lthread_setspecific(k, x) ? thrd_error : thrd_success;
}
