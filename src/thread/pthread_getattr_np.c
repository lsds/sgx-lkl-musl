#define _GNU_SOURCE
#include "pthread_impl.h"
#include "libc.h"
#include <sys/mman.h>

int pthread_getattr_np(pthread_t t, pthread_attr_t *a)
{
        pthread_attr_init(a);
        pthread_attr_setdetachstate(a, t->attr.state & BIT(LT_ST_DETACH));
        pthread_attr_setstack(a, t->attr.stack, t->attr.stack_size);
        return 0;
}
