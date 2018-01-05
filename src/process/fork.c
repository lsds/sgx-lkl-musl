#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "syscall.h"
#include "libc.h"
#include <errno.h>

static void dummy(int x)
{
}

weak_alias(dummy, __fork_handler);

pid_t fork(void)
{
        errno = ENOSYS;
        return -1;
}
