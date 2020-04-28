#include "pthread_impl.h"

int __pthread_key_create(pthread_key_t *k, void (*dtor)(void *))
{
	return lthread_key_create(k, dtor);
}

weak_alias(__pthread_key_create, pthread_key_create);
