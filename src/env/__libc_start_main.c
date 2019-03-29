#include <elf.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "syscall.h"
#include "atomic.h"
#include "libc.h"
#include <time.h>
#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"

#include "sgx_enclave_config.h"
#include "enclave_mem.h"
#include "sgx_hostcall_interface.h"
#include "lthread.h"
#include "pthread_impl.h"
#include "sgxlkl_debug.h"
#include "sgxlkl_util.h"

#ifdef SGXLKL_HW
#include <setjmp.h>
#endif

static void dummy(void) {}
weak_alias(dummy, _init);

extern weak hidden void (*const __init_array_start)(void), (*const __init_array_end)(void);

static void dummy1(void *p) {}
weak_alias(dummy1, __init_ssp);

extern void init_sysconf(long nproc_conf, long nproc_onln);
_Noreturn void __dls3(enclave_config_t *encl, void *tos);

#ifdef SGXLKL_HW
extern void* _dlstart_c(enclave_config_t *encl);

void init_dso(char* base);
void reloc_all();
void decode_dyn();
#else
void (*sim_exit_handler) (int);
#endif

#define AUX_CNT 38

extern struct mpmcq __scheduler_queue;
extern struct mpmcq *__syscall_queue;
extern struct mpmcq *__return_queue;

int sgxlkl_verbose = 1;

// Enclave config saved in startmain() for exitmain().
static enclave_config_t *encl_config = NULL;

struct timespec sgxlkl_app_starttime;

struct lkl_host_operations lkl_host_ops;
struct lkl_host_operations sgxlkl_host_ops;

#ifdef __GNUC__
__attribute__((__noinline__))
#endif

static size_t *init_aux(size_t *auxv_base) {
    size_t i, aux_base[AUX_CNT] = { 0 };
    for (i = 0; auxv_base[i]; i += 2)
        if (auxv_base[i] < AUX_CNT)
            aux_base[auxv_base[i]] = auxv_base[i + 1];

    // By default auxv[AT_RANDOM] points to a buffer with 16 random bytes.
    uint64_t *rbuf = malloc(16);
    // TODO Use intrinsics
    // if (!_rdrand64_step(&rbuf[0]))
    //    goto err;
    register uint64_t rd;
    __asm__ volatile ( "rdrand %0;" : "=r" ( rd ) );
    rbuf[0] = rd;
    __asm__ volatile ( "rdrand %0;" : "=r" ( rd ) );
    rbuf[1] = rd;

    size_t *auxv = malloc(24 * sizeof(*auxv));
    memset(auxv, 0, 24 * sizeof(*auxv));
    auxv[0]  = AT_CLKTCK;   auxv[1]  = 100;
    auxv[2]  = AT_EXECFN;   auxv[3]  = "";
    auxv[4]  = AT_HWCAP;    auxv[5]  = auxv_base[AT_HWCAP];
    auxv[6]  = AT_EGID;     auxv[7]  = 0;
    auxv[8]  = AT_EUID;     auxv[9]  = 0;
    auxv[10] = AT_GID;      auxv[11] = 0;
    auxv[12] = AT_PAGESZ;   auxv[13] = auxv_base[AT_PAGESZ];
    auxv[14] = AT_PLATFORM; auxv[15] = "x86_64";
    auxv[16] = AT_SECURE;   auxv[17] = 0;
    auxv[18] = AT_UID;      auxv[19] = 0;
    auxv[20] = AT_RANDOM;   auxv[21] = rbuf;
    auxv[22] = AT_NULL;     auxv[23] = 0;


    return auxv;
}

void __init_libc(char **envp, char *pn, enclave_config_t *encl)
{
    size_t i, *auxv, aux[AUX_CNT] = { 0 };
    __environ = envp;
    for (i=0; envp[i]; i++);
    libc.auxv = auxv = init_aux((void *)(envp+i+1));
    for (i=0; auxv[i]; i+=2) if (auxv[i]<AUX_CNT) aux[auxv[i]] = auxv[i+1];
    __hwcap = aux[AT_HWCAP];
    __sysinfo = aux[AT_SYSINFO];
    libc.page_size = aux[AT_PAGESZ];

    if (!pn) pn = (void*)aux[AT_EXECFN];
    if (!pn) pn = "";
    __progname = __progname_full = pn;
    for (i=0; pn[i]; i++) if (pn[i]=='/') __progname = pn+i+1;

    __init_ssp((void *)aux[AT_RANDOM]);

    if (aux[AT_UID]==aux[AT_EUID] && aux[AT_GID]==aux[AT_EGID]
        && !aux[AT_SECURE]) return;

    struct pollfd pfd[3] = { {.fd=0}, {.fd=1}, {.fd=2} };
    int r =
#ifdef SYS_poll
    __syscall(SYS_poll, pfd, 3, 0);
#else
    __syscall(SYS_ppoll, pfd, 3, &(struct timespec){0}, 0, _NSIG/8);
#endif
    if (r<0) a_crash();
    for (i=0; i<3; i++) if (pfd[i].revents&POLLNVAL)
        if (__sys_open("/dev/null", O_RDWR)<0)
            a_crash();
    libc.secure = 1;

}

static void libc_start_init(void)
{
    _init();
    uintptr_t a = (uintptr_t)&__init_array_start;
    for (; a<(uintptr_t)&__init_array_end; a+=sizeof(void(*)()))
        (*(void (**)(void))a)();

}

weak_alias(libc_start_init, __libc_start_init);

typedef int lsm2_fn(int (*)(int,char **,char **), int, char **);
static lsm2_fn libc_start_main_stage2;

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
    if (!getenv_bool("SGXLKL_VERBOSE", 0)) {
        sgxlkl_verbose = 0;
        sgxlkl_host_ops.print = NULL;
        lkl_host_ops.print = NULL;
    }

#ifdef SGXLKL_HW
    size_t i;
    if (getenv("SGXLKL_VERBOSE")) {
        for (i = 0; i < sizeof(ps)/sizeof(ps[0]); i++) {
            SGXLKL_VERBOSE("%s: %lu\n", ps[i].name, getenv_uint64(ps[i].name, ps[i].def, ps[i].max));
        }
        SGXLKL_VERBOSE("__libc_version: %s\n", __libc_version);
        SGXLKL_VERBOSE("Maximum enclave threads (TCS): %d\n", get_enclave_parms()->tcsn);
    }
#endif

    __libc_start_init();
    a_barrier();
    __libc_state = 2;
    // Save the enclave config for exit handlers
    encl_config = encl;

#ifndef SGXLKL_HW
    sim_exit_handler = encl->sim_exit_handler;
#endif

    int res = atexit(exitmain);
    if (res != 0)
        fprintf(stderr, "WARN: unable to register exit handler, code %d\n", res);

    // Setup LKL (hd, net, memory) and start a kernel (synchronous method)

    // SGX-LKL lthreads inherit names from their parent. Set this to "kernel"
    // temporarily to be able to identify LKL kernel threads.
    lthread_set_funcname(lthread_self(), "kernel");
    __lkl_start_init(encl);
    lthread_set_funcname(lthread_self(), "sgx-lkl-init");

    // Launch stage 3 dynamic linker, passing in top of stack to overwrite.
    // The dynamic linker will then load the application proper; here goes!
    __dls3(encl, __builtin_frame_address(0));
}

/* 1 - initialization in progress, 2 - initialized */
int __libc_init_enclave(int argc, char **argv, enclave_config_t *encl)
{
    struct lthread *lt;
    libc.vvar_base = encl->vvar;
    libc.user_tls_enabled = encl->mode == SGXLKL_HW_MODE ? encl->fsgsbase : 1;
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
    char **envp = argv + argc + 1;
    enclave_mman_init(encl->heap, encl->heapsize / PAGESIZE);

    init_sysconf(encl->sysconf_nproc_conf, encl->sysconf_nproc_onln);

    size_t max_lthreads = encl->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_pow2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    __syscall_queue = &encl->syscallq;
    __return_queue = &encl->returnq;

    hostsyscallclient_init(encl);

    __init_libc(envp, argv[0], encl);
    __init_tls();

     size_t futex_wake_spins = getenv_uint64("SGXLKL_GETTIME_VDSO", 0, ULONG_MAX) == 1 ? 1 : 500;
     size_t espins = getenv_uint64("SGXLKL_ESPINS", 500, ULONG_MAX);
     size_t esleep = getenv_uint64("SGXLKL_ESLEEP", 16000, ULONG_MAX);
     lthread_sched_global_init(espins, esleep, futex_wake_spins);

    _lthread_sched_init(encl->stacksize);

#ifdef SGXLKL_HW
    // Once host syscalls are available, remove all permissions from the
    // zero page so that a null pointer dereference will cause a segfault.
    if (encl->heap == 0) {
        if (mprotect(0, PAGESIZE, PROT_NONE)) {
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

    /* External linkage, and explicit noinline attribute if available,
     * are used to prevent the stack frame used during init from
     * persisting for the entire process lifetime. */
    // libc is already inited at this point, don't init it again.
    //__init_libc(envp, argv[0]);

    /* Barrier against hoisting application code or anything using ssp
     * or thread pointer prior to its initialization above. */
    lsm2_fn *stage2 = libc_start_main_stage2;
    __asm__ ( "" : "+r"(stage2) : : "memory" );
    return stage2(main, argc, argv);
}

static int libc_start_main_stage2(int (*main)(int,char **,char **), int argc, char **argv)
{
    char **envp = argv+argc+1;
    __libc_start_init();

    SGXLKL_VERBOSE("Calling main()\n");

    if (getenv_bool("SGXLKL_PRINT_APP_RUNTIME", 0)) {
        clock_gettime(CLOCK_MONOTONIC, &sgxlkl_app_starttime);
    }
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
    enclave_config_t* encl = (enclave_config_t*)arg;
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
            __sgx_lkl_start_main(encl);
            break;
        }
        default:
            exit_enclave(SGXLKL_EXIT_ERROR, SGXLKL_UNEXPECTED_CALLID, get_exit_address(), UNUSED);
            break;
    }
}
#endif
