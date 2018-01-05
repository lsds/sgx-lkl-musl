#include "pthread_impl.h"

int lthread_setspecific(pthread_key_t key, const void *value);

int pthread_setspecific(pthread_key_t k, const void *x)
{
        return lthread_setspecific(k, x);
}
