#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <poll.h>
#include "atomic.h"
#include "enclave_config.h"
#include "enclave_mman.h"
#include "libc.h"
#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"
#include "lthread.h"
#include "pthread_impl.h"
#include "sgxlkl_debug.h"
#include "syscall.h"
#include "hostqueues.h"
#include "hostsyscallclient.h"

#ifdef SGXLKL_HW
#include <setjmp.h>
#endif

int sgxlkl_verbose = 1;

void __init_utls(size_t, Elf64_Phdr *);
void __init_tls(void);

static void dummy(void) {}
weak_alias(dummy, _init);
weak_alias(dummy, _preinit);

__attribute__((__weak__, __visibility__("hidden")))
extern void (*const __preinit_array_start)(void), (*const __preinit_array_end)(void);

__attribute__((__weak__, __visibility__("hidden")))
extern void (*const __init_array_start)(void), (*const __init_array_end)(void);

extern void init_sysconf(long nproc_conf, long nproc_onln);

_Noreturn void __dls3(enclave_config_t *encl, void *tos);

static void dummy1(void *p) {}
weak_alias(dummy1, __init_ssp);
const char *__libc_get_version();

#ifdef SGXLKL_HW
extern void* _dlstart_c(enclave_config_t *encl);

void init_dso(char* base);
void reloc_all();
void decode_dyn();
#endif

#define AUX_CNT 38

// Enclave config saved in startmain() just for exitmain()
static enclave_config_t *encl_config = NULL;

extern int get_env_bool(const char *name, int def);
struct lkl_host_operations lkl_host_ops;
struct lkl_host_operations sgxlkl_host_ops;

// Used as a tag in the binary to prevent executable compiled with debug options
// from being used in benchmarks
#ifdef DEBUG
const volatile char musl_compile_version[] = "sgx-lkl v1.0.0 DEBUG";
#else
const volatile char musl_compile_version[] = "sgx-lkl v1.0.0";
#endif

void __init_libc(char **envp, char *pn, enclave_config_t *encl)
{
	size_t i, *auxv, aux[AUX_CNT] = { 0 };
	__environ = envp;
	for (i=0; envp[i]; i++);
	libc.auxv = auxv = (void *)(envp+i+1);
	for (i=0; auxv[i]; i+=2) if (auxv[i]<AUX_CNT) aux[auxv[i]] = auxv[i+1];
	__hwcap = aux[AT_HWCAP];
	__sysinfo = aux[AT_SYSINFO];
	libc.page_size = aux[AT_PAGESZ];

	if (!pn) pn = (void*)aux[AT_EXECFN];
	if (!pn) pn = "";
	__progname = __progname_full = pn;
	for (i=0; pn[i]; i++) if (pn[i]=='/') __progname = pn+i+1;

#ifndef SGXLKL_HW
    if (encl->tlspresent) {
        __init_utls(encl->tlsbase, &encl->tlsphdr);
    }
#else
    __init_utls(0, 0);
#endif
    __init_ssp((void *)aux[AT_RANDOM]);


    if (aux[AT_UID]==aux[AT_EUID] && aux[AT_GID]==aux[AT_EGID]
        && !aux[AT_SECURE]) return;


    struct pollfd pfd[3] = { {.fd=0}, {.fd=1}, {.fd=2} };
#ifdef SYS_poll
    __syscall(SYS_poll, pfd, 3, 0);
#else
    __syscall(SYS_ppoll, pfd, 3, &(struct timespec){0}, 0, _NSIG/8);
#endif
    for (i=0; i<3; i++) if (pfd[i].revents&POLLNVAL)
        if (__sys_open("/dev/null", O_RDWR)<0)
            a_crash();
    libc.secure = 1;

}

static size_t parseenv(const char *var, size_t def, size_t max)
{
        size_t r = def;
        char *val;
        if ((val = getenv(var))) {
                r = strtoul(val, NULL, 10);
                if (r == ULONG_MAX) {
                        r = def;
                }
                if (r > max) {
                        r = max;
                }
        }
        return r;
}

static void __libc_start_preinit(void)
{
    _preinit();
    uintptr_t a = (uintptr_t)&__preinit_array_start;
    for (; a<(uintptr_t)&__preinit_array_end; a+=sizeof(void(*)()))
        (*(void (**)())a)();
}

static void __libc_start_init(void)
{
    _init();
    uintptr_t a = (uintptr_t)&__init_array_start;
    for (; a<(uintptr_t)&__init_array_end; a+=sizeof(void(*)()))
        (*(void (**)(void))a)();
}

static void exitmain(void)
{
	if (encl_config == NULL) {
		fprintf(stderr, "WARN: exitmain() called but no encl_conf provided.\n");
		return;
	}
	__lkl_exit();
}


static int __libc_state = 0;
static int startmain(enclave_config_t *encl) {
        const struct {
                const char *name; size_t def; size_t max;
        } ps[] = {
                {"SGXLKL_ETHREADS", 2, ULONG_MAX},
                {"SGXLKL_STHREADS", 1, ULONG_MAX},
                {"SGXLKL_MAX_USER_THREADS", 256, 100000},
                {"SGXLKL_SIGPIPE", 0, ULONG_MAX},
                {"SGXLKL_REAL_TIME_PRIO", 0, ULONG_MAX},
                {"SGXLKL_ESPINS", 500, ULONG_MAX},
                {"SGXLKL_ESLEEP", 16000, ULONG_MAX},
                {"SGXLKL_SSPINS", 100, ULONG_MAX},
                {"SGXLKL_SSLEEP", 4000, ULONG_MAX},
                {"SGXLKL_HEAP", 4096*200000, ULONG_MAX},
        };

        // Disable kernel outputs for normal runs
        //TODO: keep in a separate buffer instead of discarding
        if (!get_env_bool("SGXLKL_VERBOSE", 0)) {
            sgxlkl_verbose = 0;
            sgxlkl_host_ops.print = NULL;
            lkl_host_ops.print = NULL;
        }

#ifdef SGXLKL_HW
        size_t i;
        if (getenv("SGXLKL_VERBOSE")) {
                for (i = 0; i < sizeof(ps)/sizeof(ps[0]); i++) {
                    SGXLKL_VERBOSE("%s: %zu\n", ps[i].name, parseenv(ps[i].name, ps[i].def, ps[i].max));
                }
                SGXLKL_VERBOSE("__libc_get_version: %s\n", __libc_get_version());
                SGXLKL_VERBOSE("Maximum enclave threads (TCS): %d\n", get_enclave_parms()->tcsn);
        }
#endif

        __libc_start_preinit();
        __libc_start_init();
        a_barrier();
        __libc_state = 2;
	// Save the enclave config for exit handlers
	encl_config = encl;
	int res = atexit(exitmain);
	if (res != 0)
		fprintf(stderr, "WARN: unable to register exit handler, code %d\n", res);

	// Setup LKL (hd, net, memory) and start a kernel (synchronous method)
	__lkl_start_init(encl);

	// Launch stage 3 dynamic linker, passing in top of stack to overwrite.
	// The dynamic linker will then load the application proper; here goes!
	__dls3(encl, __builtin_frame_address(0));
}

/* 1 - initialization in progress, 2 - initialized */
int __libc_init_enclave(int argc, char **argv, enclave_config_t *encl)
{
        struct lthread *lt;
        libc.vvar_base = encl->vvar;
#ifndef SGXLKL_HW
        int c;
        while ((c = a_cas(&__libc_state, 0, 1)) == 1) {a_spin();}
        if (c == 2) {
                __init_tls();
                _lthread_sched_init(encl->stacksize);
                lthread_run();
                return 0;
        }
#endif
        char **envp = argv+argc+1;
        enclave_mman_init(encl->heap, encl->heapsize/PAGESIZE);

        init_sysconf(encl->sysconf_nproc_conf, encl->sysconf_nproc_onln);

        __initschedqueue(5000); /* max lthreads */
        __initsyscallqueues(&encl->syscallq, &encl->returnq);
        hostsyscallclient_init(encl);

        __init_libc(envp, argv[0], encl);
        __init_tls();
         size_t futex_wake_spins = parseenv("SGXLKL_GETTIME_VDSO", 0, ULONG_MAX) == 1 ? 1 : 500;
         lthread_sched_global_init(parseenv("SGXLKL_ESPINS", 500, ULONG_MAX), parseenv("SGXLKL_ESLEEP", 16000, ULONG_MAX), futex_wake_spins);
        /* You shall not pass control to the application */
        _lthread_sched_init(encl->stacksize);

#ifdef SGXLKL_HW
	// Once host syscalls are available, remove all permissions from the
	// zero page so that a null pointer dereference will cause a segfault.
        if(encl->heap == 0) {
                if(mprotect(0, PAGESIZE, PROT_NONE)) {
                        fprintf(stderr, "WARN: Unable to set page permissions for zero page: %s\n", strerror(errno));

                }
        }

#endif /* SGXLKL_HW */

        /* You shall not pass control to the application */
        if (lthread_create(&lt, NULL, startmain, encl) == -1) {
                exit(-1);
        }
        lthread_run();
        return 0;
}

int __libc_start_main(int (*main)(int,char **,char **), int argc, char **argv)
{
	char **envp = argv+argc+1;

	// libc is already inited at this point, don't init it again.
	//__init_libc(envp, argv[0]);

	__libc_start_init();

    SGXLKL_VERBOSE("Calling main()\n");

	/* Pass control to the application */
	exit(main(argc, argv, envp));
	return 0;
}

#ifdef SGXLKL_HW
int __sgx_lkl_start_main(enclave_config_t *encl)
{
    encl->base = (void*)get_enclave_parms()->base;
    encl->heap = (void*)get_enclave_parms()->heap;
    encl->heapsize = get_enclave_parms()->heap_size;

    _dlstart_c(encl);

    __libc_init_enclave(encl->argc, encl->argv, encl);
    return 0;
}

void __sgx_lkl_entry(uint64_t call_id, void* arg) {
    switch (call_id) {
        case SGXLKL_ENTER_THREAD_CREATE: {
            int c;
            while ((c = a_cas(&__libc_state, 0, 1)) == 1) {a_spin();}
            if (c == 2) {
                __init_tls();
                _lthread_sched_init(0);
                lthread_run();
                return;
            }
            enclave_config_t* encl = (enclave_config_t*)arg;
            __sgx_lkl_start_main(encl);
            break;
        }
        default:
            exit_enclave(SGXLKL_EXIT_ERROR, SGXLKL_UNEXPECTED_CALLID, get_exit_address(), UNUSED);
            break;
    }
}
#endif
