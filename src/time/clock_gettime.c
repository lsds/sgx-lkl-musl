#include <time.h>
#include <errno.h>
#include <stdint.h>
#include "syscall.h"
#include "atomic.h"
#include "libc.h"

#include <enclave/enclave_oe.h>

#ifdef VDSO_CGT_SYM

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

static int vdso_read_begin(const struct vsyscall_gtod_data *s)
{
	unsigned ret;

retry:
	ret = s->seq;
	if (ret & 1)
		goto retry;


	a_barrier();
	return ret;
}

static int vdso_read_retry(const struct vsyscall_gtod_data *s, unsigned start)
{
	a_barrier();
	return s->seq != start;
}

static uint64_t rdtsc_ordered(void)
{
	uint64_t low, high, ret;
	a_barrier();
	__asm("rdtscp" : "=a"(low), "=d"(high) : : "rcx");
	return (high << 32) + low;
}

#define VCLOCK_TSC 1

static uint64_t vgetsns(const volatile struct vsyscall_gtod_data *s, int volatile *mode)
{
	uint64_t v;
	uint64_t cycles;

	if (s->vclock_mode == VCLOCK_TSC) {
		uint64_t rdtsc = (uint64_t)rdtsc_ordered();
		uint64_t last = s->cycle_last;
		cycles = (rdtsc >= last) ? rdtsc : last;
	} else
		return 0;

	v = (cycles - s->cycle_last) & s->mask;
	return v * s->mult;
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
