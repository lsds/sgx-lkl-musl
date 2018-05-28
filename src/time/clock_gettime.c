#include <time.h>
#include <errno.h>
#include <stdint.h>
#include "syscall.h"
#include "libc.h"
#include "atomic.h"
#include "sgxlkl_debug.h"
#include "hostqueues.h"

#ifdef VDSO_CGT_SYM

void *__vdsosym(const char *, const char *);

static void *volatile vdso_func;

static int cgt_init(clockid_t clk, struct timespec *ts)
{
	void *p = __vdsosym(VDSO_CGT_VER, VDSO_CGT_SYM);
	int (*f)(clockid_t, struct timespec *) =
		(int (*)(clockid_t, struct timespec *))p;
	a_cas_p(&vdso_func, (void *)cgt_init, p);
	return f ? f(clk, ts) : -ENOSYS;
}

static void *volatile vdso_func = (void *)cgt_init;

#endif

/* Straight from linux::arch/x86/include/asm/vgtod.h */
typedef uint64_t gtod_long_t;
struct vsyscall_gtod_data {
	unsigned seq;

	int vclock_mode;
	uint64_t	cycle_last;
	uint64_t	mask;
	uint32_t	mult;
	uint32_t	shift;

	/* open coded 'struct timespec' */
	uint64_t	wall_time_snsec;
	gtod_long_t	wall_time_sec;
	gtod_long_t	monotonic_time_sec;
	uint64_t	monotonic_time_snsec;
	gtod_long_t	wall_time_coarse_sec;
	gtod_long_t	wall_time_coarse_nsec;
	gtod_long_t	monotonic_time_coarse_sec;
	gtod_long_t	monotonic_time_coarse_nsec;

	int		tz_minuteswest;
	int		tz_dsttime;
};

/* Straight from linux::arch/x86/include/asm/vvar.h */
static int __vsyscall_gtod_data_offset = 128;

static inline uint32_t
__iter_div_u64_rem(uint64_t dividend, uint32_t divisor, uint64_t *remainder)
{
	uint32_t ret = 0;

	while (dividend >= divisor) {
		/* The following asm() prevents the compiler from
		   optimising this loop into a modulo operation.  */
		__asm__("" : "+rm"(dividend));

		dividend -= divisor;
		ret++;
	}

	*remainder = dividend;

	return ret;
}

static inline int
vdso_read_begin(const struct vsyscall_gtod_data *s)
{
	unsigned ret;

retry:
	ret = s->seq;
	if (ret & 1)
		goto retry;


	a_barrier();
	return ret;
}

static inline int
vdso_read_retry(const struct vsyscall_gtod_data *s, unsigned start)
{
	a_barrier();
	return s->seq != start;
}

int __clock_gettime(clockid_t clk, struct timespec *ts)
{
	int r;
#ifdef VDSO_CGT_SYM
	int (*f)(clockid_t, struct timespec *) =
		(int (*)(clockid_t, struct timespec *))vdso_func;
	if (f) {
		r = f(clk, ts);
		if (!r) return r;
		if (r == -EINVAL) return __syscall_ret(r);
		/* Fall through on errors other than EINVAL. Some buggy
		 * vdso implementations return ENOSYS for clocks they
		 * can't handle, rather than making the syscall. This
		 * also handles the case where cgt_init fails to find
		 * a vdso function to use. */
	}
#endif

	if (libc.vvar_base && clk == CLOCK_REALTIME) {
		volatile struct vsyscall_gtod_data *ptr = (char *)libc.vvar_base + __vsyscall_gtod_data_offset;
		unsigned seq;
		uint64_t ns;

//		do {
			//seq = vdso_read_begin(ptr);
			seq = ptr->seq;
			ts->tv_sec = ptr->wall_time_sec;
			ns = ptr->wall_time_snsec;
			ns >>= ptr->shift;
//		} while (vdso_read_retry(ptr, seq));

		ts->tv_sec += __iter_div_u64_rem(ns, 1000000000L, &ns);
		ts->tv_nsec = ns;

		return __syscall_ret(0);
	}

	r = __syscall(SYS_clock_gettime, clk, ts);
	if (r == -ENOSYS) {
		if (clk == CLOCK_REALTIME) {
			__syscall(SYS_gettimeofday, ts, 0);
			ts->tv_nsec = (int)ts->tv_nsec * 1000;
			return 0;
		}
		r = -EINVAL;
	}
	return __syscall_ret(r);
}

weak_alias(__clock_gettime, clock_gettime);
