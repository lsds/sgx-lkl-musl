#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "syscall.h"

int faccessat(int fd, const char *filename, int amode, int flag)
{
	if (!flag || (flag==AT_EACCESS && getuid()==geteuid() && getgid()==getegid()))
		return syscall(SYS_faccessat, fd, filename, amode, flag);

	if (flag != AT_EACCESS)
		return __syscall_ret(-EINVAL);

	int ret = -EBUSY;

        ret = __syscall(SYS_faccessat, fd, filename, amode, 0);

	return __syscall_ret(ret);
}
