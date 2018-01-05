#include "pthread_impl.h"
#include "libc.h"

static pthread_t __pthread_self_internal()
{
	return lthread_self();
}

weak_alias(__pthread_self_internal, pthread_self);
