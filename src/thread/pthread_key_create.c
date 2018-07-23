#include "pthread_impl.h"

int lthread_key_create(pthread_key_t *k, void (*destructor)(void*));
int lthread_key_delete(pthread_key_t key);

int __pthread_key_create(pthread_key_t *k, void (*dtor)(void *))
{
	return lthread_key_create(k, dtor);
}

int __pthread_key_delete(pthread_key_t k)
{
	return lthread_key_delete(k);
}

weak_alias(__pthread_key_delete, pthread_key_delete);
weak_alias(__pthread_key_create, pthread_key_create);
