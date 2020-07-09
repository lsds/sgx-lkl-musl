#define _GNU_SOURCE
#include "pthread_impl.h"
#include "libc.h"
#include <sys/mman.h>
#include <enclave/lthread.h>

int pthread_getattr_np(pthread_t t, pthread_attr_t *a)
{
	*a = (pthread_attr_t){0};
	a->_a_detach = t->detach_state>=DT_DETACHED;
	a->_a_guardsize = t->guard_size;
	if (t->stack) {
		a->_a_stackaddr = (uintptr_t)t->stack;
		a->_a_stacksize = t->stack_size;
	} else {
		/**
		 * pthreads doesn't know about the stack of the main thread
		 * and tries calculate the stackaddr relative to the aux vector
		 * As currently the aux vector is not on the stack, the following
		 * calculation is no longer correct.
		*/
		// char *p = (void *)libc.auxv;
		// size_t l = PAGE_SIZE;
		// p += -(uintptr_t)p & PAGE_SIZE-1;
		// a->_a_stackaddr = (uintptr_t)p;
		// while (mremap(p-l-PAGE_SIZE, PAGE_SIZE, 2*PAGE_SIZE, 0)==MAP_FAILED && errno==ENOMEM)
		// 	l += PAGE_SIZE;
		// a->_a_stacksize = l;
		/**
		 * As a temporary solution fetch stack address and size
		 * from lthread. Remove when aux vector is properly setup.
		 */
		struct lthread* lt = lthread_current();
		pthread_attr_setstack(a, lt->attr.stack, lt->attr.stack_size);
	}
	return 0;
}
