#include <time.h>
#include <setjmp.h>
#include "pthread_impl.h"

struct ksigevent {
	union sigval sigev_value;
	int sigev_signo;
	int sigev_notify;
	int sigev_tid;
};

int timer_create(clockid_t clk, struct sigevent *restrict evp, timer_t *restrict res)
{
	struct ksigevent ksev, *ksevp=0;
	int timerid;
	sigset_t set;

	switch (evp ? evp->sigev_notify : SIGEV_SIGNAL) {
	case SIGEV_NONE:
	case SIGEV_SIGNAL:
		if (evp) {
			ksev.sigev_value = evp->sigev_value;
			ksev.sigev_signo = evp->sigev_signo;
			ksev.sigev_notify = evp->sigev_notify;
			ksev.sigev_tid = 0;
			ksevp = &ksev;
		}
		if (syscall(SYS_timer_create, clk, ksevp, &timerid) < 0)
			return -1;
		*res = (void *)(intptr_t)timerid;
		break;
	case SIGEV_THREAD:
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}
