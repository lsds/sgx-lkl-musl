#include <time.h>
#include <limits.h>
#include "syscall.h"

int timer_getoverrun(timer_t t)
{
    return syscall(SYS_timer_getoverrun, (intptr_t)t);
}
