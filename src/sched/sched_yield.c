#include <sched.h>
#include <lthread.h>
#include "lthread_int.h"
#include "syscall.h"

int sched_yield()
{
        /* 
         * lthread_yield does not add the current thread to the end of scheduler
         * queue. We have to enqueue this thread after entering the scheduler
         * because otherwise there is a chance of a race condition -- Another
         * scheduler might pick up this lthread while the current scheduler is
         * still executing it.
         */
        struct lthread *lt = lthread_self();
        _lthread_yield_cb(lt, (void *)__scheduler_enqueue, lt);
	return 0;
}
