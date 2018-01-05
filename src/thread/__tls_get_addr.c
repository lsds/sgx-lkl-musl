#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"

__attribute__((__visibility__("hidden")))
void *__tls_get_new(size_t *);

void *__tls_get_addr(size_t *v)
{
    /* current_lthread->tls + v[1] */
    struct lthread_sched *sch = lthread_get_sched();
    struct lthread *lt = sch->current_lthread;
    return (char *)lt->itls+v[1]+DTP_OFFSET;
}

weak_alias(__tls_get_addr, __tls_get_new);
