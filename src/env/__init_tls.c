#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"
#include "atomic.h"
#include "syscall.h"
#include "enclave/enclave_oe.h"
#include "enclave/lthread.h"
#include "enclave/enclave_util.h"

static int spawned_ethreads = 1;

struct pthread
{
};

int __init_tp(void *p)
{
	struct schedctx *td = p;

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
	if (libc.user_tls_enabled && set_tp)
	{
		if (sgxlkl_in_sw_debug_mode())
		{
			int r = __set_thread_area(TP_ADJ(p));
			if (r < 0)
			{
				sgxlkl_fail("Could not set thread area %p: %s\n", p, strerror(errno));
			}
		}
		else
		{
			__asm__ volatile("wrfsbase %0" ::"r"(p));
		}
	}
	return 0;
}

static struct builtin_tls
{
	char c;
	struct schedctx *pt;
	void *space[16];
} builtin_tls[1];
#define MIN_TLS_ALIGN offsetof(struct builtin_tls, pt)

static struct tls_module main_tls;

/* Set up user-level thread TLS */
void *__copy_utls(struct lthread *lt, unsigned char *mem, size_t sz)
{
	struct tls_module *p;
	size_t i;
	uintptr_t *dtv;

	dtv = (uintptr_t *)mem;

	mem += sz - sizeof(struct lthread_tcb_base);
	mem -= (uintptr_t)mem & (libc.tls_align - 1);

	for (i = 1, p = libc.tls_head; p; i++, p = p->next)
	{
		dtv[i] = (uintptr_t)(mem - p->offset) + DTP_OFFSET;
		memcpy(mem - p->offset, p->image, p->len);
	}
	dtv[0] = libc.tls_cnt;
	lt->dtv = lt->dtv_copy = dtv;
	return (void *)mem;
}

/* Initialisation of user-level thread TLS image */
void __init_utls(struct tls_module *apptls)
{
	if (apptls && apptls->image)
	{
		main_tls = *apptls;
		libc.tls_cnt = 1;
		libc.tls_head = &main_tls;
	}

	main_tls.size += (-main_tls.size - (uintptr_t)main_tls.image) & (main_tls.align - 1);
	main_tls.offset = main_tls.size;
	if (main_tls.align < MIN_TLS_ALIGN)
		main_tls.align = MIN_TLS_ALIGN;

	libc.tls_align = main_tls.align;
	libc.tls_size = 2 * sizeof(void *) + sizeof(struct lthread_tcb_base) + main_tls.size + main_tls.align + MIN_TLS_ALIGN - 1 & -MIN_TLS_ALIGN;
}

/* Initialisation of ethread/scheduler TLS */
static void static_init_tls()
{
	void *mem = __scheduler_self();

	/* Failure to initialize thread pointer is always fatal. */
	if (__init_tp(mem) < 0)
		a_crash();
}

weak_alias(static_init_tls, __init_tls);
