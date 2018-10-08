#ifndef _INTERNAL_SYSCALL_H
#define _INTERNAL_SYSCALL_H

#include <lthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "syscall_arch.h"
#include "hostsyscalls.h"
#include "sgxlkl_debug.h"

#ifndef SYSCALL_RLIM_INFINITY
#define SYSCALL_RLIM_INFINITY (~0ULL)
#endif

#ifndef SYSCALL_MMAP2_UNIT
#define SYSCALL_MMAP2_UNIT 4096ULL
#endif

#ifndef __SYSCALL_LL_PRW
#define __SYSCALL_LL_PRW(x) __SYSCALL_LL_O(x)
#endif

#ifndef __scc
#define __scc(X) ((long) (X))
typedef long syscall_arg_t;
#endif

__attribute__((visibility("hidden")))
long __syscall_ret(unsigned long), __syscall(syscall_arg_t, ...),
	__syscall_cp(syscall_arg_t, syscall_arg_t, syscall_arg_t, syscall_arg_t,
	             syscall_arg_t, syscall_arg_t, syscall_arg_t);

const char* lkl_strerror(int err);

extern int sgxlkl_trace_lkl_syscall;
extern int sgxlkl_trace_internal_syscall;
extern int sgxlkl_use_host_network;

#undef __LKL_SYSCALL
#define __LKL_SYSCALL(nr) { (const char*)(__lkl__NR_ ## nr), #nr },
#include <lkl.h>
static const char* __lkl_syscall_names[][2] = {
#include <lkl/syscalls.h>
	{ NULL, NULL },
#undef __LKL_SYSCALL
};

#ifdef DEBUG
static inline void __log_syscall(int type, long n, long res, int params_len, ...)
{
	const char* name = NULL;
	char errmsg[255] = {0};

	if (!sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL)
		return;

	if (!sgxlkl_trace_internal_syscall && type == SGXLKL_INTERNAL_SYSCALL)
		return;

	long params[6] = {0};
	va_list valist;
        va_start(valist, params_len);
        for(int i = 0; i < params_len; i++) {
		params[i] = va_arg(valist, long);
	}
	va_end(valist);

	for (int i = 0; __lkl_syscall_names[i][1] != NULL; i++) {
		if ((long)__lkl_syscall_names[i][0] == n) {
			name = __lkl_syscall_names[i][1];
			break;
		}
	}

	if (name == NULL)
		name = "### INVALID ###";
	if (res < 0)
		snprintf(errmsg, sizeof(errmsg), " (%s) <--- !", lkl_strerror(res));

	int tid = lthread_self() ? lthread_self()->tid : 0;
	if (n == SYS_open || n == SYS_lstat) {
		SGXLKL_TRACE_SYSCALL(type, "[tid=%-3d] %s\t%ld\t(%s, %ld, %ld, %ld) = %ld %s\n", tid, name, n,
			(const char*)(params[0]), params[1], params[2], params[3], res, errmsg);
	} else if (n == SYS_execve) {
	    SGXLKL_TRACE_SYSCALL(type, "[tid=%-3d] %s\t%ld\t(%s, %s, %s, %ld, %ld) = %ld %s\n", tid, name, n,
			(const char*)(params[0]), ((const char**)params[1])[0], ((const char**)params[1])[1], params[2], params[3], res, errmsg);
	} else {
	    SGXLKL_TRACE_SYSCALL(type, "[tid=%-3d] %s\t%ld\t(%ld, %ld, %ld, %ld, %ld, %ld) = %ld%s\n", tid, name, n,
			params[0], params[1], params[2], params[3], params[4], params[5], res, errmsg);
	}
}
#else
static inline void __log_syscall(int type, long n, long res, int params_len, ...) { /* empty */ }
#endif

static inline long __filter_syscall0(long n) {
	long params[6] = {0};
	if (n == SYS_gettid) {
		long res = (long)lthread_id();
		__log_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 0);
		return res;
	} else if (n == SYS_munlockall) {
		return (long)host_syscall_SYS_munlockall();
	} else {
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 0);
		return res;
	}
}

static inline long __filter_syscall1(long n, long a1) {
	long params[6] = {0};
	if (n == SYS_set_tid_address) {
		return (long)host_syscall_SYS_set_tid_address((int*)a1);
	} else if (n == SYS_exit) {
		host_syscall_SYS_exit((int)a1);
		return 42;
	} else if (n == SYS_exit_group) {
		host_syscall_SYS_exit_group((int)a1);
		return 42;
	} else {
		params[0] = a1;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 1, a1);

		return res;
	}
}

static inline long __filter_syscall2(long n, long a1, long a2) {
	long params[6] = {0};

	if (n == SYS_kill) {
		return (long)host_syscall_SYS_kill((pid_t)a1, (int)a2);
	} else if (n == SYS_tkill) {
		return (long)host_syscall_SYS_tkill((int)a1, (int)a2);
	} else if (n == SYS_munmap) {
		long res = (long)syscall_SYS_munmap((void*)a1, (size_t)a2);
		__log_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 2, a1, a2);
		return res;
	} else if (n == SYS_nanosleep) {
		return (long)host_syscall_SYS_nanosleep((const struct timespec*)a1, (struct timespec*)a2);
	} else if (n == SYS_clock_gettime) {
		return (long)host_syscall_SYS_clock_gettime((clockid_t)a1, (struct timespec*)a2);
	} else if (n == SYS_clock_getres) {
		return (long)host_syscall_SYS_clock_getres((clockid_t)a1, (struct timespec*)a2);
	} else if (n == SYS_stat) {
		struct lkl_stat tmp_stat;
		params[0] = a1;
		params[1] = (long) &tmp_stat;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 2, a1, a2);
		if (res == 0) {
			struct stat *res_stat = (struct stat*) a2;

			res_stat->st_dev = tmp_stat.st_dev;
			res_stat->st_ino = tmp_stat.st_ino;
			res_stat->st_mode = tmp_stat.st_mode;
			res_stat->st_nlink = tmp_stat.st_nlink;
			res_stat->st_uid = tmp_stat.st_uid;
			res_stat->st_gid = tmp_stat.st_gid;
			res_stat->st_rdev = tmp_stat.st_rdev;
			res_stat->st_size = tmp_stat.st_size;
			res_stat->st_blksize = tmp_stat.st_blksize;
			res_stat->st_blocks = tmp_stat.st_blocks;
			res_stat->st_atim.tv_sec = tmp_stat.lkl_st_atime;
			res_stat->st_atim.tv_nsec = tmp_stat.st_atime_nsec;
			res_stat->st_mtim.tv_sec = tmp_stat.lkl_st_mtime;
			res_stat->st_mtim.tv_nsec = tmp_stat.st_mtime_nsec;
			res_stat->st_ctim.tv_sec = tmp_stat.lkl_st_ctime;
			res_stat->st_ctim.tv_nsec = tmp_stat.st_ctime_nsec;
		}
	      	return res;
	} else if (n == SYS_fstat && (a1 == STDIN_FILENO || a1 == STDOUT_FILENO || a1 == STDERR_FILENO)) {
                return (long)host_syscall_SYS_fstat((int)a1, (struct stat *)a2);
	} else if (n == SYS_sigaltstack) {
		return (long)host_syscall_SYS_sigaltstack((stack_t*)a1, (stack_t*)a2);
	} else if (n == SYS_rt_sigpending) {
		return (long)host_syscall_SYS_rt_sigpending((sigset_t *)a1, (unsigned long)a2);
	} else if (n == SYS_rt_sigsuspend) {
		return (long)host_syscall_SYS_rt_sigsuspend((sigset_t *)a1, (unsigned long)a2);
	} else {
		params[0] = a1;
		params[1] = a2;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 2, a1, a2);

		return res;
	}
}

static inline long __filter_syscall3(long n, long a1, long a2, long a3) {
	long params[6] = {0};

	if (n == SYS_writev && (a1 == STDOUT_FILENO || a1 == STDERR_FILENO)) {
		return (long)host_syscall_SYS_writev((int)a1, (const struct iovec*)a2, (int)a3);
	} else if (n == SYS_write && (a1 == STDOUT_FILENO || a1 == STDERR_FILENO)) {
		return (long)host_syscall_SYS_write((int)a1, (const void*)a2, (long)a3);
	} else if (n == SYS_ioctl && (a1 == STDOUT_FILENO || a1 == STDERR_FILENO || a1 == STDIN_FILENO)) {
		return (long)host_syscall_SYS_ioctl((int)a1, (unsigned long)a2, (void*)a3);
	} else if (n == SYS_read && (a1 == STDIN_FILENO)) {
		return (long)host_syscall_SYS_read((int)a1, (char*)a2, (size_t)a3);
	} else if (n == SYS_readv && (a1 == STDIN_FILENO)) {
		return (long)host_syscall_SYS_readv((int)a1, (struct iovec*)a2, (int)a3);
	} else if (n == SYS_msync) {
		return (long)syscall_SYS_msync((void*)a1, (size_t)a2, (int)a3);
	} else if (n == SYS_mprotect) {
		return (long)host_syscall_SYS_mprotect((void*)a1, (size_t)a2, (int)a3);
	} else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 3, a1, a2, a3);

		return res;
	}
}

static inline long __filter_syscall4(long n, long a1, long a2, long a3, long a4) {
	long params[6] = {0};
	if (n == SYS_rt_sigprocmask) {
		return (long)host_syscall_SYS_rt_sigprocmask((int)a1, (void*)a2, (sigset_t*)a3, (unsigned long)a4);
	} else if (n == SYS_rt_sigtimedwait) {
		return (long)host_syscall_SYS_rt_sigtimedwait((sigset_t *)a1, (siginfo_t*)a2, (struct timespec*)a3, (unsigned long)a4);
	}
#ifndef SGXLKL_HW
	else if (n == SYS_rt_sigaction && a1 == SIGSEGV) {
		return (long) host_syscall_SYS_rt_sigaction((int)a1, (struct sigaction *)a2, (struct sigaction *)a3, (unsigned long)a4);
	}
#endif
	else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 4, a1, a2, a3, a4);

		return res;
	}
}

static inline long __filter_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
	long params[6] = {0};
	if (n == SYS_mremap) {
		long res = (long)syscall_SYS_mremap((void*)a1, (size_t)a2, (size_t)a3, (int)a4, (void*)a5);
		__log_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 5, a1, a2, a3, a4, a5);
		return res;
	} else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		params[4] = a5;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 5, a1, a2, a3, a4, a5);

		return res;
	}
}

static inline long __filter_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
	long params[6] = {0};
	if (n == SYS_mmap) {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		params[4] = a5;
		params[5] = a6;
		if (a4 == MAP_PRIVATE || a4 == MAP_SHARED)
		{
			params[3]=MAP_PRIVATE;
			long res = lkl_syscall(n, params);
			__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);

			return res;
		}
		else
		{
			long res = (long)syscall_SYS_mmap((void*)a1, (size_t)a2, (int)a3, (int)a4, (int)a5, (off_t)a6);
			__log_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);
			return res;
		}

	} else if (n == SYS_futex) {
		long res = (long)syscall_SYS_futex((int*)a1, (int)a2, (int)a3, (const struct timespec*)a4,
			(int*)a5, (int)a6);
		__log_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);
		return res;
	} else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		params[4] = a5;
		params[5] = a6;
		long res = lkl_syscall(n, params);
		__log_syscall(SGXLKL_LKL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);

		return res;
	}
}

#define __filter_syscall0(n) __filter_syscall0(n)
#define __filter_syscall1(n,a) __filter_syscall1(n,(long)(a))
#define __filter_syscall2(n,a,b) __filter_syscall2(n,(long)(a),(long)(b))
#define __filter_syscall3(n,a,b,c) __filter_syscall3(n,(long)(a),(long)(b),(long)(c))
#define __filter_syscall4(n,a,b,c,d) __filter_syscall4(n,(long)(a),(long)(b),(long)(c),(long)(d))
#define __filter_syscall5(n,a,b,c,d,e) __filter_syscall5(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e))
#define __filter_syscall6(n,a,b,c,d,e,f) __filter_syscall6(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))

#define __SYSCALL_NARGS_X(a,b,c,d,e,f,g,h,n,...) n
#define __SYSCALL_NARGS(...) __SYSCALL_NARGS_X(__VA_ARGS__,7,6,5,4,3,2,1,0,)
#define __SYSCALL_CONCAT_X(a,b) a##b
#define __SYSCALL_CONCAT(a,b) __SYSCALL_CONCAT_X(a,b)
#define __SYSCALL_DISP(b,...) __SYSCALL_CONCAT(b,__SYSCALL_NARGS(__VA_ARGS__))(__VA_ARGS__)

#define __syscall(...) __SYSCALL_DISP(__filter_syscall,__VA_ARGS__)
#define syscall(...) __syscall_ret(__syscall(__VA_ARGS__))

#define socketcall __socketcall
#define socketcall_cp __socketcall_cp

#define __syscall_cp(...) __SYSCALL_DISP(__filter_syscall,__VA_ARGS__)
#define syscall_cp(...) __syscall_ret(__syscall_cp(__VA_ARGS__))

#define __socketcall(nm,a,b,c,d,e,f) syscall(SYS_##nm, a, b, c, d, e, f)
#define __socketcall_cp(nm,a,b,c,d,e,f) syscall_cp(SYS_##nm, a, b, c, d, e, f)

/* fixup legacy 16-bit junk */

#ifdef SYS_getuid32
#undef SYS_lchown
#undef SYS_getuid
#undef SYS_getgid
#undef SYS_geteuid
#undef SYS_getegid
#undef SYS_setreuid
#undef SYS_setregid
#undef SYS_getgroups
#undef SYS_setgroups
#undef SYS_fchown
#undef SYS_setresuid
#undef SYS_getresuid
#undef SYS_setresgid
#undef SYS_getresgid
#undef SYS_chown
#undef SYS_setuid
#undef SYS_setgid
#undef SYS_setfsuid
#undef SYS_setfsgid
#define SYS_lchown SYS_lchown32
#define SYS_getuid SYS_getuid32
#define SYS_getgid SYS_getgid32
#define SYS_geteuid SYS_geteuid32
#define SYS_getegid SYS_getegid32
#define SYS_setreuid SYS_setreuid32
#define SYS_setregid SYS_setregid32
#define SYS_getgroups SYS_getgroups32
#define SYS_setgroups SYS_setgroups32
#define SYS_fchown SYS_fchown32
#define SYS_setresuid SYS_setresuid32
#define SYS_getresuid SYS_getresuid32
#define SYS_setresgid SYS_setresgid32
#define SYS_getresgid SYS_getresgid32
#define SYS_chown SYS_chown32
#define SYS_setuid SYS_setuid32
#define SYS_setgid SYS_setgid32
#define SYS_setfsuid SYS_setfsuid32
#define SYS_setfsgid SYS_setfsgid32
#endif


/* fixup legacy 32-bit-vs-lfs64 junk */

#ifdef SYS_fcntl64
#undef SYS_fcntl
#define SYS_fcntl SYS_fcntl64
#endif

#ifdef SYS_getdents64
#undef SYS_getdents
#define SYS_getdents SYS_getdents64
#endif

#ifdef SYS_ftruncate64
#undef SYS_ftruncate
#undef SYS_truncate
#define SYS_ftruncate SYS_ftruncate64
#define SYS_truncate SYS_truncate64
#endif

#ifdef SYS_stat64
#undef SYS_stat
#define SYS_stat SYS_stat64
#endif

#ifdef SYS_fstat64
#undef SYS_fstat
#define SYS_fstat SYS_fstat64
#endif

#ifdef SYS_lstat64
#undef SYS_lstat
#define SYS_lstat SYS_lstat64
#endif

#ifdef SYS_statfs64
#undef SYS_statfs
#define SYS_statfs SYS_statfs64
#endif

#ifdef SYS_fstatfs64
#undef SYS_fstatfs
#define SYS_fstatfs SYS_fstatfs64
#endif

#if defined(SYS_newfstatat)
#undef SYS_fstatat
#define SYS_fstatat SYS_newfstatat
#elif defined(SYS_fstatat64)
#undef SYS_fstatat
#define SYS_fstatat SYS_fstatat64
#endif

#ifdef SYS_ugetrlimit
#undef SYS_getrlimit
#define SYS_getrlimit SYS_ugetrlimit
#endif

#ifdef SYS__newselect
#undef SYS_select
#define SYS_select SYS__newselect
#endif

#ifdef SYS_pread64
#undef SYS_pread
#undef SYS_pwrite
#define SYS_pread SYS_pread64
#define SYS_pwrite SYS_pwrite64
#endif

#ifdef SYS_fadvise64_64
#undef SYS_fadvise
#define SYS_fadvise SYS_fadvise64_64
#elif defined(SYS_fadvise64)
#undef SYS_fadvise
#define SYS_fadvise SYS_fadvise64
#endif

#ifdef SYS_sendfile64
#undef SYS_sendfile
#define SYS_sendfile SYS_sendfile64
#endif

/* socketcall calls */

#define __SC_socket      1
#define __SC_bind        2
#define __SC_connect     3
#define __SC_listen      4
#define __SC_accept      5
#define __SC_getsockname 6
#define __SC_getpeername 7
#define __SC_socketpair  8
#define __SC_send        9
#define __SC_recv        10
#define __SC_sendto      11
#define __SC_recvfrom    12
#define __SC_shutdown    13
#define __SC_setsockopt  14
#define __SC_getsockopt  15
#define __SC_sendmsg     16
#define __SC_recvmsg     17
#define __SC_accept4     18
#define __SC_recvmmsg    19
#define __SC_sendmmsg    20

#define __sys_open2(x,pn,fl) __filter_syscall2(SYS_open, pn, (fl)|O_LARGEFILE)
#define __sys_open3(x,pn,fl,mo) __filter_syscall3(SYS_open, pn, (fl)|O_LARGEFILE, mo)
#define __sys_open_cp2(x,pn,fl) __filter_syscall2(SYS_open, pn, (fl)|O_LARGEFILE)
#define __sys_open_cp3(x,pn,fl,mo) __filter_syscall3(SYS_open, pn, (fl)|O_LARGEFILE, mo)

#define __sys_open(...) __SYSCALL_DISP(__sys_open,,__VA_ARGS__)
#define sys_open(...) __syscall_ret(__sys_open(__VA_ARGS__))

#define __sys_open_cp(...) __SYSCALL_DISP(__sys_open_cp,,__VA_ARGS__)
#define sys_open_cp(...) __syscall_ret(__sys_open_cp(__VA_ARGS__))

#endif
