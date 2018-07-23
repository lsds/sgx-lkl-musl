#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"
#include "atomic.h"
#include "syscall.h"
#include "hostsyscalls.h"
#include "lthread.h"

struct pthread {};

int __init_tp(void *p)
{
//#ifndef SGXLKL_HW
        struct schedctx *td = p;
	td->self = td;
	int r = __set_thread_area(TP_ADJ(p));
	if (r < 0) return -1;
	if (!r) libc.can_do_threads = 1;
	td->tid = __syscall(SYS_set_tid_address, &td->tid);
	td->locale = &libc.global_locale;
	td->robust_list.head = &td->robust_list.head;
//#else
//        libc.can_do_threads = 1;
//#endif
        return 0;
}

static struct builtin_tls {
	char c;
	struct schedctx pt;
	void *space[16];
} builtin_tls[1];
#define MIN_TLS_ALIGN offsetof(struct builtin_tls, pt)

static struct tls_module main_tls;

void *__copy_tls(unsigned char *mem)
{
	struct schedctx *td;
	struct tls_module *p;
	size_t i;
	void **dtv;

	dtv = (void **)mem;

	mem += libc.tls_size - sizeof(struct schedctx);
	mem -= (uintptr_t)mem & (libc.tls_align-1);
	td = (struct schedctx *)mem;

	for (i=1, p=libc.tls_head; p; i++, p=p->next) {
		dtv[i] = mem - p->offset;
		memcpy(dtv[i], p->image, p->len);
	}
	dtv[0] = (void *)libc.tls_cnt;
	td->dtv = td->dtv_copy = dtv;
	return td;
}

#if ULONG_MAX == 0xffffffff
typedef Elf32_Phdr Phdr;
#else
typedef Elf64_Phdr Phdr;
#endif


int __copy_utls(uint8_t **mem, size_t *sz)
{
        if (main_tls.size == 0) {
                return 1;
        }
        *mem = mmap(0, main_tls.size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if (*mem == MAP_FAILED) {
                return 0;
        }
        mprotect(main_tls.image, main_tls.len, PROT_READ); 
        mprotect(*mem, main_tls.len, PROT_READ|PROT_WRITE); 
        memcpy(*mem, main_tls.image, main_tls.len);
        *sz = main_tls.size;
        return 1;
}

void __init_utls(size_t base, Elf64_Phdr *tls_phdr)
{
#ifndef SGXLKL_HW
    /* this initialization is done only for userspace threads */
    if (tls_phdr) {
        main_tls.image = (void *)(base + tls_phdr->p_vaddr);
        main_tls.len = tls_phdr->p_filesz;
        main_tls.size = tls_phdr->p_memsz;
        main_tls.align = tls_phdr->p_align;
        libc.tls_cnt = 1;
        libc.tls_head = &main_tls;
    }
#else
        main_tls.image = (void*)(get_enclave_parms()->tls_vaddr + get_enclave_parms()->base);
        main_tls.len = get_enclave_parms()->tls_filesz;
        main_tls.size = get_enclave_parms()->tls_memsz;
        main_tls.align = 8;//FIXME
        libc.tls_cnt = 1;
        libc.tls_head = &main_tls;
#endif
        
	main_tls.size += (-main_tls.size - (uintptr_t)main_tls.image)
		& (main_tls.align-1);
	if (main_tls.align < MIN_TLS_ALIGN) main_tls.align = MIN_TLS_ALIGN;
	main_tls.offset = main_tls.size;

	libc.tls_align = main_tls.align;
	libc.tls_size = 2*sizeof(void *) + sizeof(struct schedctx)
		+ main_tls.size + main_tls.align
		+ MIN_TLS_ALIGN-1 & -MIN_TLS_ALIGN;
}

static void static_init_tls()
{
    /* this initializes scheduler TLS */
    size_t sTLSsize = sizeof(struct schedctx);
    void *mem;

    mem = (void *)__syscall(
            SYS_mmap,
            0, sTLSsize, PROT_READ|PROT_WRITE,
            MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    /* -4095...-1 cast to void * will crash on dereference anyway,
     * so don't bloat the init code checking for error codes and
     * explicitly calling a_crash(). */

    /* Failure to initialize thread pointer is always fatal. */
    if (__init_tp(mem) < 0)
        a_crash();
}

weak_alias(static_init_tls, __init_tls);
