#include "pthread_impl.h"

int __pthread_key_create(pthread_key_t *k, void (*dtor)(void *))
{
	return ENOSYS;
}

int __pthread_key_delete(pthread_key_t k)
{
	return 0;
}

weak_alias(__pthread_key_delete, pthread_key_delete);
weak_alias(__pthread_key_create, pthread_key_create);
