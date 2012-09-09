#define _GNU_SOURCE
#include <sys/uio.h>
#include <unistd.h>
#include "syscall.h"
#include "libc.h"

ssize_t preadv(int fd, const struct iovec *iov, int count, off_t ofs)
{
	return syscall_cp(SYS_preadv, fd, iov, count,
		(long)(ofs), (long)(ofs>>32));
}

LFS64(preadv);