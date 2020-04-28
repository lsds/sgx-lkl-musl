#include "pthread_impl.h"

int pthread_setspecific(pthread_key_t k, const void *x)
{
        return lthread_setspecific(k, x);
}
