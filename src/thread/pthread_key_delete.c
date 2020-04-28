#include "pthread_impl.h"
#include "libc.h"

int __pthread_key_delete(pthread_key_t k)
{
	return lthread_key_delete(k);
}

weak_alias(__pthread_key_delete, pthread_key_delete);
