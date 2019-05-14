#ifndef _INTERNAL_SYSCALL_H
#define _INTERNAL_SYSCALL_H

#include <features.h>
#include <lthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "syscall_arch.h"
#include "enclave_mem.h"
#include "sgx_hostcalls.h"
#include "sgxlkl_debug.h"
#include "lkl.h"

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


hidden long __syscall_ret(unsigned long), __syscall(syscall_arg_t, ...),
	__syscall_cp(syscall_arg_t, syscall_arg_t, syscall_arg_t, syscall_arg_t,
	             syscall_arg_t, syscall_arg_t, syscall_arg_t);

static const long SYSCALLS_NOOP[] = {
                SYS_munlock,
                SYS_munlockall,
                SYS_set_tid_address
                };
static const long SYSCALLS_NOT_IMPLEMENTED[] = {
                SYS_sigaltstack,
                SYS_kill,
                SYS_brk,
                SYS_sched_setaffinity
                };

static int is_noop(long no) {
	for (size_t i = 0; i < sizeof(SYSCALLS_NOOP) / sizeof(SYSCALLS_NOOP[0]); i++)
		if (SYSCALLS_NOOP[i] == no)
			return 1;
	return 0;
}

static int not_implemented(long no) {
	for (size_t i = 0; i < sizeof(SYSCALLS_NOT_IMPLEMENTED) / sizeof(SYSCALLS_NOT_IMPLEMENTED[0]); i++)
		if (SYSCALLS_NOT_IMPLEMENTED[i] == no)
			return 1;
	return 0;
}

static void copy_lkl_stat_to_user(struct lkl_stat *lkl_stat, struct stat *stat) {
	stat->st_dev = lkl_stat->st_dev;
	stat->st_ino = lkl_stat->st_ino;
	stat->st_mode = lkl_stat->st_mode;
	stat->st_nlink = lkl_stat->st_nlink;
	stat->st_uid = lkl_stat->st_uid;
	stat->st_gid = lkl_stat->st_gid;
	stat->st_rdev = lkl_stat->st_rdev;
	stat->st_size = lkl_stat->st_size;
	stat->st_blksize = lkl_stat->st_blksize;
	stat->st_blocks = lkl_stat->st_blocks;
	stat->st_atim.tv_sec = lkl_stat->lkl_st_atime;
	stat->st_atim.tv_nsec = lkl_stat->st_atime_nsec;
	stat->st_mtim.tv_sec = lkl_stat->lkl_st_mtime;
	stat->st_mtim.tv_nsec = lkl_stat->st_mtime_nsec;
	stat->st_ctim.tv_sec = lkl_stat->lkl_st_ctime;
	stat->st_ctim.tv_nsec = lkl_stat->st_ctime_nsec;
}

static inline long __filter_syscall0(long n) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};
	if (n == SYS_gettid) {
		long res = (long)lthread_id();
		log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 0);
		return res;
	} else {
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 0);
		return res;
	}
}

static inline long __filter_syscall1(long n, long a1) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};

	if (n == SYS_sysinfo) {
		long res = (long) syscall_SYS_sysinfo((struct sysinfo *) a1);
		log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 1, a1);
		return res;
	} else {
		params[0] = a1;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 1, a1);

		return res;
	}
}

static inline long __filter_syscall2(long n, long a1, long a2) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};

	if (n == SYS_tkill) {
		return (long)host_syscall_SYS_tkill((int)a1, (int)a2);
	} else if (n == SYS_munmap) {
		long res = (long)syscall_SYS_munmap((void*)a1, (size_t)a2);
		log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 2, a1, a2);
		return res;
	} else if (n == SYS_nanosleep) {
		return (long)host_syscall_SYS_nanosleep((const struct timespec*)a1, (struct timespec*)a2);
	} else if (n == SYS_clock_gettime) {
		// Force call to go through libc clock_gettime implementation to make use of the vDSO path.
		clockid_t clk = (clockid_t) a1;
		struct timespec *ts = (struct timespec *) a2;
		if (libc.vvar_base && (clk == CLOCK_REALTIME || clk == CLOCK_MONOTONIC ||
		                       clk == CLOCK_REALTIME_COARSE || clk == CLOCK_MONOTONIC_COARSE)) {
			return clock_gettime(clk, ts);
		}
		return (long)host_syscall_SYS_clock_gettime(clk, ts);
	} else if (n == SYS_clock_getres) {
		return (long)host_syscall_SYS_clock_getres((clockid_t)a1, (struct timespec*)a2);
	} else if (n == SYS_fstat && !(a1 == STDIN_FILENO || a1 == STDOUT_FILENO || a1 == STDERR_FILENO)) {
		struct lkl_stat tmp_stat;
		params[0] = a1;
		params[1] = (long) &tmp_stat;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 2, a1, a2);
		if (res == 0) {
			copy_lkl_stat_to_user(&tmp_stat, (struct stat*) a2);
		}
	      	return res;
	} else if (n == SYS_fstat && (a1 == STDIN_FILENO || a1 == STDOUT_FILENO || a1 == STDERR_FILENO)) {
                return (long)host_syscall_SYS_fstat((int)a1, (struct stat *)a2);
	} else if (n == SYS_rt_sigpending) {
		return (long)host_syscall_SYS_rt_sigpending((sigset_t *)a1, (unsigned long)a2);
	} else if (n == SYS_rt_sigsuspend) {
		return (long)host_syscall_SYS_rt_sigsuspend((sigset_t *)a1, (unsigned long)a2);
	} else {
		params[0] = a1;
		params[1] = a2;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 2, a1, a2);

		return res;
	}
}

static inline long __filter_syscall3(long n, long a1, long a2, long a3) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

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
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 3, a1, a2, a3);

		return res;
	}
}

static inline long __filter_syscall4(long n, long a1, long a2, long a3, long a4) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};

	if (n == SYS_rt_sigprocmask) {
		return (long)host_syscall_SYS_rt_sigprocmask((int)a1, (void*)a2, (sigset_t*)a3, (unsigned long)a4);
	} else if (n == SYS_rt_sigtimedwait) {
		return (long)host_syscall_SYS_rt_sigtimedwait((sigset_t *)a1, (siginfo_t*)a2, (struct timespec*)a3, (unsigned long)a4);
	} else if (n == SYS_newfstatat) {
		struct lkl_stat tmp_stat;
		params[0] = a1;
		params[1] = a2;
		params[2] = (long) &tmp_stat;
		params[3] = a4;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 2, a1, a2, a3, a4);
		if (res == 0) {
			copy_lkl_stat_to_user(&tmp_stat, (struct stat*) a3);
		}
		return res;
	}
#ifndef SGXLKL_HW
	else if (n == SYS_rt_sigaction && (a1 == SIGSEGV || a1 == SIGFPE)) {
		return (long) host_syscall_SYS_rt_sigaction((int)a1, (struct sigaction *)a2, (struct sigaction *)a3, (unsigned long)a4);
	}
#endif
	else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 4, a1, a2, a3, a4);

		return res;
	}
}

static inline long __filter_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};

	if (n == SYS_mremap) {
		long res = (long)syscall_SYS_mremap((void*)a1, (size_t)a2, (size_t)a3, (int)a4, (void*)a5);
		log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 5, a1, a2, a3, a4, a5);
		return res;
	} else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		params[4] = a5;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 5, a1, a2, a3, a4, a5);

		return res;
	}
}

static inline long __filter_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
	if (is_noop(n)) return 0;
	if (not_implemented(n)) return -ENOSYS;

	long params[6] = {0};

	if (n == SYS_mmap) {
		if (enclave_mmap_flags_supported((int) a4, (int) a5)) {
			long res = (long)syscall_SYS_mmap((void*)a1, (size_t)a2, (int)a3, (int)a4, (int)a5, (off_t)a6);
			log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);
			return res;
		// If SGX-LKL can't handle mmap request, try LKL.
		} else {
			params[0] = a1;
			params[1] = a2;
			params[2] = a3;
			params[3] = MAP_PRIVATE;
			params[4] = a5;
			params[5] = a6;
			long res = lkl_syscall(n, params);
			log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);
			return res;
		}
	} else if (n == SYS_futex) {
		long res = (long)syscall_SYS_futex((int*)a1, (int)a2, (int)a3, (const struct timespec*)a4,
			(int*)a5, (int)a6);
		log_sgxlkl_syscall(SGXLKL_INTERNAL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);
		return res;
	} else {
		params[0] = a1;
		params[1] = a2;
		params[2] = a3;
		params[3] = a4;
		params[4] = a5;
		params[5] = a6;
		long res = lkl_syscall(n, params);
		log_sgxlkl_syscall(SGXLKL_LKL_SYSCALL, n, res, 6, a1, a2, a3, a4, a5, a6);

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

#ifndef SYSCALL_USE_SOCKETCALL
#define __socketcall(nm,a,b,c,d,e,f) syscall(SYS_##nm, a, b, c, d, e, f)
#define __socketcall_cp(nm,a,b,c,d,e,f) syscall_cp(SYS_##nm, a, b, c, d, e, f)
#else
#define __socketcall(nm,a,b,c,d,e,f) syscall(SYS_socketcall, __SC_##nm, \
    ((long [6]){ (long)a, (long)b, (long)c, (long)d, (long)e, (long)f }))
#define __socketcall_cp(nm,a,b,c,d,e,f) syscall_cp(SYS_socketcall, __SC_##nm, \
    ((long [6]){ (long)a, (long)b, (long)c, (long)d, (long)e, (long)f }))
#endif

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

#ifdef SYS_open
#define __sys_open2(x,pn,fl) __filter_syscall2(SYS_open, pn, (fl)|O_LARGEFILE)
#define __sys_open3(x,pn,fl,mo) __filter_syscall3(SYS_open, pn, (fl)|O_LARGEFILE, mo)
#define __sys_open_cp2(x,pn,fl) __filter_syscall2(SYS_open, pn, (fl)|O_LARGEFILE)
#define __sys_open_cp3(x,pn,fl,mo) __filter_syscall3(SYS_open, pn, (fl)|O_LARGEFILE, mo)
#else
#define __sys_open2(x,pn,fl) __filter_syscall3(SYS_openat, AT_FDCWD, pn, (fl)|O_LARGEFILE)
#define __sys_open3(x,pn,fl,mo) __filter_syscall4(SYS_openat, AT_FDCWD, pn, (fl)|O_LARGEFILE, mo)
#define __sys_open_cp2(x,pn,fl) __filter_syscall3(SYS_openat, AT_FDCWD, pn, (fl)|O_LARGEFILE)
#define __sys_open_cp3(x,pn,fl,mo) __filter_syscall4(SYS_openat, AT_FDCWD, pn, (fl)|O_LARGEFILE, mo)
#endif

#define __sys_open(...) __SYSCALL_DISP(__sys_open,,__VA_ARGS__)
#define sys_open(...) __syscall_ret(__sys_open(__VA_ARGS__))

#define __sys_open_cp(...) __SYSCALL_DISP(__sys_open_cp,,__VA_ARGS__)
#define sys_open_cp(...) __syscall_ret(__sys_open_cp(__VA_ARGS__))

hidden void __procfdname(char __buf[static 15+3*sizeof(int)], unsigned);

hidden void *__vdsosym(const char *, const char *);

#endif
