#include "pthread_impl.h"

int pthread_getcpuclockid(pthread_t t, clockid_t *clockid)
{
	*clockid = 0;
	return 0;
}
