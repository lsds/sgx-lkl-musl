#include <errno.h>
#include "pthread_impl.h"

int *__errno_location(void)
{
        struct schedctx *sch = __scheduler_self();
        struct lthread *lt = sch->sched.current_lthread;
        return lt ? &lt->err : &sch->errno_val;
}

weak_alias(__errno_location, ___errno_location);
