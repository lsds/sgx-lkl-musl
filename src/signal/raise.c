#include <signal.h>
#include <stdint.h>
#include "syscall.h"
#include "pthread_impl.h"
#include <lkl.h>

int raise(int sig)
{
    int tid, pid, ret;
    sigset_t set;
    long params[6] = {0};

    __block_app_sigs(&set);

    /* We need to obtain the pid and tid from LKL so that we use
    the kernel mapped pid, tid for the lthread involved. */
    pid = lkl_syscall(SYS_getpid, params);
    tid = lkl_syscall(SYS_gettid, params);

    ret = syscall(SYS_tgkill, pid, tid, sig);
    __restore_sigs(&set);
    return ret;
}
