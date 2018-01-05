#include "pthread_impl.h"
#include <sys/mman.h>

int __pthread_join(pthread_t t, void **res)
{
        if (t == 0) {
                return ESRCH;
        }
        return lthread_join(t, res, WAIT_LIMITLESS);
}

weak_alias(__pthread_join, pthread_join);
