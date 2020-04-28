#include "enclave/lthread_int.h"
#include <enclave/lthread.h>

int __pthread_setcancelstate(int new, int *old)
{
    return lthread_setcancelstate(new, old);
}

weak_alias(__pthread_setcancelstate, pthread_setcancelstate);
