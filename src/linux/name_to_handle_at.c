#define _GNU_SOURCE
#include <fcntl.h>
#include "syscall.h"

int name_to_handle_at(int dirfd, const char *pathname,
	struct file_handle *handle, int *mount_id, int flags)
{
	// name_to_handle_at system call not defined for LKL (up to at least
	// 4.19)
	//return syscall(SYS_name_to_handle_at, dirfd,
	//	pathname, handle, mount_id, flags);
	return ENOSYS;
}
