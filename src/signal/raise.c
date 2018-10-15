#include <signal.h>
#include <stdint.h>
#include "syscall.h"
#include "pthread_impl.h"
#include "hostcall_interface.h"

int raise(int sig)
{
    int tid, ret;
    sigset_t set;
    __block_app_sigs(&set);
#ifdef SGXLKL_HW
    tid = host_syscall_SYS_gettid();
    int pid = __syscall(SYS_getpid);
    ret = syscall(SYS_tgkill, pid, tid, sig);
#else
    tid = __syscall(SYS_gettid);
    ret = syscall(SYS_tkill, tid, sig);
#endif
    __restore_sigs(&set);
    return ret;
}
