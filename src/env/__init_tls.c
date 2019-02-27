#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"
#include "atomic.h"
#include "syscall.h"
#include "sgx_hostcalls.h"
#include "lthread.h"

static int spawned_ethreads = 1;

struct pthread {};

int __init_tp(void *p)
{
#ifdef SGXLKL_HW
	struct schedctx *td = p;
	// Store pointer to enclave_parms in scheduling context to make it accessible
	// from an lthread context
	enclave_parms_t* parms;
	__asm("movq %%fs:16,%0\n" : "=r"(parms) : : );
	td->enclave_parms = parms;
#else
	int r = __set_thread_area(TP_ADJ(p));
	if (r < 0) return -1;
	struct sched_tcb_base *tcb = (struct sched_tcb_base *)p;
	tcb->self = tcb;
	struct schedctx *td = (struct schedctx *) ((char *)tcb + sizeof(struct sched_tcb_base));
	tcb->schedctx = td;
#endif /* SGXLKL_HW */
	td->self = td;
	// Prevent collisions with lthread TIDs which are assigned to newly spawned
	// lthreads incrementally, starting from one.
	td->tid = INT_MAX - a_fetch_add(&spawned_ethreads, 1);
	td->locale = &libc.global_locale;
	td->robust_list.head = &td->robust_list.head;
	libc.can_do_threads = 1;
	return 0;
}

int __init_utp(void *p, int set_tp)
{
	struct lthread_tcb_base *tcb = (struct lthread_tcb_base *)p;
	tcb->self = p;
	tcb->schedctx = __scheduler_self();
	if (libc.user_tls_enabled && set_tp) {
#ifdef SGXLKL_HW
		__asm__ volatile ( "wrfsbase %0" :: "r" (p) );
#else
		int r = __set_thread_area(TP_ADJ(p));
		if(r < 0) {
			fprintf(stderr, "[SGX-LKL] Error: Could not set thread area %p: %s\n", p, strerror(errno));
		}
#endif
	}
	return 0;
}

static struct builtin_tls {
	char c;
	struct schedctx* pt;
	void *space[16];
} builtin_tls[1];
#define MIN_TLS_ALIGN offsetof(struct builtin_tls, pt)

static struct tls_module main_tls;

/* Set up user-level thread TLS */
void *__copy_utls(struct lthread *lt, unsigned char *mem, size_t sz)
{
	struct tls_module *p;
	size_t i;
	void **dtv;

	dtv = (void **)mem;

	mem += sz - sizeof(struct lthread_tcb_base);
	mem -= (uintptr_t)mem & (libc.tls_align-1);

	for (i=1, p=libc.tls_head; p; i++, p=p->next) {
		dtv[i] = mem - p->offset;
		memcpy(dtv[i], p->image, p->len);
	}
	dtv[0] = (void *)libc.tls_cnt;
	lt->dtv = lt->dtv_copy = dtv;
	return (void *) mem;
}

/* Initialisation of user-level thread TLS image */
void __init_utls(struct tls_module *apptls)
{
	if (apptls && apptls->image) {
		main_tls = *apptls;
		libc.tls_cnt = 1;
		libc.tls_head = &main_tls;
	}

	main_tls.size += (-main_tls.size - (uintptr_t)main_tls.image)
		& (main_tls.align-1);
	if (main_tls.align < MIN_TLS_ALIGN) main_tls.align = MIN_TLS_ALIGN;
	main_tls.offset = main_tls.size;

	libc.tls_align = main_tls.align;
	libc.tls_size = 2*sizeof(void *) + sizeof(struct lthread_tcb_base)
		+ main_tls.size + main_tls.align
		+ MIN_TLS_ALIGN-1 & -MIN_TLS_ALIGN;
}

/* Initialisation of ethread/scheduler TLS */
static void static_init_tls()
{
	void *mem;
#ifdef SGXLKL_HW
	mem = __scheduler_self();
#else
	size_t sched_tls_size = sizeof(struct sched_tcb_base) + sizeof(struct schedctx);
	mem = (void *)__syscall(
		SYS_mmap,
		0, sched_tls_size, PROT_READ|PROT_WRITE,
		MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	/* -4095...-1 cast to void * will crash on dereference anyway,
	 * so don't bloat the init code checking for error codes and
	 * explicitly calling a_crash(). */
#endif /* SGXLKL_HW */

	/* Failure to initialize thread pointer is always fatal. */
	if (__init_tp(mem) < 0)
		a_crash();
}

weak_alias(static_init_tls, __init_tls);
