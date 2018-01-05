#include "pthread_impl.h"

void *lthread_getspecific(pthread_key_t key);

static void *__pthread_getspecific(pthread_key_t k)
{
        return lthread_getspecific(k);
}

weak_alias(__pthread_getspecific, pthread_getspecific);
