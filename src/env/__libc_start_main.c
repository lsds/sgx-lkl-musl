#include <elf.h>
#include <poll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <libc.h>
#include <string.h>
#include "shared/env.h"

static void dummy(void) {}
weak_alias(dummy, _init);

extern weak hidden void (*const __init_array_start)(void), (*const __init_array_end)(void);

static void dummy1(void *p) {}
weak_alias(dummy1, __init_ssp);

#define AUX_CNT 38

struct timespec sgxlkl_app_starttime;

#ifdef __GNUC__
__attribute__((__noinline__))
#endif

static size_t *
init_aux(size_t *auxv_base, char *pn)
{
    size_t i, aux_base[AUX_CNT] = {0};
    for (i = 0; auxv_base[i]; i += 2)
        if (auxv_base[i] < AUX_CNT)
            aux_base[auxv_base[i]] = auxv_base[i + 1];

    // By default auxv[AT_RANDOM] points to a buffer with 16 random bytes.
    uint64_t *rbuf = malloc(16);
    // TODO Use intrinsics
    // if (!_rdrand64_step(&rbuf[0]))
    //    goto err;
    register uint64_t rd;
    __asm__ volatile("rdrand %0;"
                     : "=r"(rd));
    rbuf[0] = rd;
    __asm__ volatile("rdrand %0;"
                     : "=r"(rd));
    rbuf[1] = rd;

    size_t *auxv = malloc(24 * sizeof(*auxv));
    memset(auxv, 0, 24 * sizeof(*auxv));
    auxv[0] = AT_CLKTCK;
    auxv[1] = 100;
    auxv[2] = AT_EXECFN;
    auxv[3] = (size_t) pn;
    auxv[4] = AT_HWCAP;
    auxv[5] = aux_base[AT_HWCAP];
    auxv[6] = AT_EGID;
    auxv[7] = 0;
    auxv[8] = AT_EUID;
    auxv[9] = 0;
    auxv[10] = AT_GID;
    auxv[11] = 0;
    auxv[12] = AT_PAGESZ;
    auxv[13] = aux_base[AT_PAGESZ];
    auxv[14] = AT_PLATFORM;
    auxv[15] = (size_t) "x86_64";
    auxv[16] = AT_SECURE;
    auxv[17] = 0;
    auxv[18] = AT_UID;
    auxv[19] = 0;
    auxv[20] = AT_RANDOM;
    auxv[21] = (size_t)rbuf;
    auxv[22] = AT_NULL;
    auxv[23] = 0;

    return auxv;
}

void __init_libc(char **envp, char *pn)
{
    size_t i, *auxv, aux[AUX_CNT] = {0};
    __environ = envp;
    for (i = 0; envp[i]; i++)
        ;
    libc.auxv = auxv = init_aux((void *)(envp + i + 1), pn);
    for (i = 0; auxv[i]; i += 2)
        if (auxv[i] < AUX_CNT)
            aux[auxv[i]] = auxv[i + 1];
    __hwcap = aux[AT_HWCAP];
    __sysinfo = aux[AT_SYSINFO];
    libc.page_size = aux[AT_PAGESZ];

    if (!pn)
        pn = (void *)aux[AT_EXECFN];
    if (!pn)
        pn = "";
    __progname = __progname_full = pn;
    for (i = 0; pn[i]; i++)
        if (pn[i] == '/')
            __progname = pn + i + 1;

    __init_ssp((void *)aux[AT_RANDOM]);

    if (aux[AT_UID] == aux[AT_EUID] && aux[AT_GID] == aux[AT_EGID] && !aux[AT_SECURE])
        return;

    struct pollfd pfd[3] = {{.fd = 0}, {.fd = 1}, {.fd = 2}};
    int r =
#ifdef SYS_poll
        __syscall(SYS_poll, pfd, 3, 0);
#else
        __syscall(SYS_ppoll, pfd, 3, &(struct timespec){0}, 0, _NSIG / 8);
#endif
    if (r < 0)
        a_crash();
    for (i = 0; i < 3; i++)
        if (pfd[i].revents & POLLNVAL)
            if (__sys_open("/dev/null", O_RDWR) < 0)
                a_crash();
    libc.secure = 1;
}

static void libc_start_init(void)
{
    _init();
    uintptr_t a = (uintptr_t)&__init_array_start;
    for (; a < (uintptr_t)&__init_array_end; a += sizeof(void (*)()))
        (*(void (**)(void))a)();
}

weak_alias(libc_start_init, __libc_start_init);

typedef int lsm2_fn(int (*)(int, char **, char **), int, char **);
static lsm2_fn libc_start_main_stage2;

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv)
{
    char **envp = argv + argc + 1;

    /* External linkage, and explicit noinline attribute if available,
     * are used to prevent the stack frame used during init from
     * persisting for the entire process lifetime. */
    // libc is already inited at this point, don't init it again.
    //__init_libc(envp, argv[0]);

    /* Barrier against hoisting application code or anything using ssp
     * or thread pointer prior to its initialization above. */
    lsm2_fn *stage2 = libc_start_main_stage2;
    __asm__(""
            : "+r"(stage2)
            :
            : "memory");
    return stage2(main, argc, argv);
}

static int libc_start_main_stage2(int (*main)(int, char **, char **), int argc, char **argv)
{
    char **envp = argv + argc + 1;
    __libc_start_init();

    SGXLKL_VERBOSE("Calling app main: %s\n", argv[0]);

    if (getenv_bool("SGXLKL_PRINT_APP_RUNTIME", 0))
    {
        clock_gettime(CLOCK_MONOTONIC, &sgxlkl_app_starttime);
    }
    /* Pass control to the application */
    exit(main(argc, argv, envp));
    return 0;
}
