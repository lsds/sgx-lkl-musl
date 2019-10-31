#include <elf.h>
#include <poll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <atomic.h>
#include <libc.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "attest.h"
#include "enclave_cmd.h"
#include "enclave_mem.h"
#include "lkl/asm/host_ops.h"
#include "lkl/setup.h"
#include "lthread.h"
#include "pthread.h"
#include "pthread_impl.h"
#include "sgx_enclave_config.h"
#include "sgx_hostcall_interface.h"
#include "sgxlkl_debug.h"
#include "sgxlkl_util.h"
#include "wireguard.h"
#include "wireguard_util.h"

#ifdef SGXLKL_HW
#include <setjmp.h>
#include "sgx_enclave_report.h"
#include "sgx_report.h"
#endif

static void dummy(void) {}
weak_alias(dummy, _init);

extern weak hidden void (*const __init_array_start)(void), (*const __init_array_end)(void);

static void dummy1(void *p) {}
weak_alias(dummy1, __init_ssp);

extern void init_sysconf(long nproc_conf, long nproc_onln);
_Noreturn void __dls3(sgxlkl_app_config_t *conf, void *tos);

#ifdef SGXLKL_HW
extern void* _dlstart_c(size_t base);

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

struct timespec sgxlkl_app_starttime;

struct lkl_host_operations lkl_host_ops;
struct lkl_host_operations sgxlkl_host_ops;

#ifdef __GNUC__
__attribute__((__noinline__))
#endif

static size_t *init_aux(size_t *auxv_base, char *pn) {
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
    auxv[2]  = AT_EXECFN;   auxv[3]  = (size_t) (pn ? pn : "");
    auxv[4]  = AT_HWCAP;    auxv[5]  = aux_base[AT_HWCAP];
    auxv[6]  = AT_EGID;     auxv[7]  = 0;
    auxv[8]  = AT_EUID;     auxv[9]  = 0;
    auxv[10] = AT_GID;      auxv[11] = 0;
    auxv[12] = AT_PAGESZ;   auxv[13] = aux_base[AT_PAGESZ];
    auxv[14] = AT_PLATFORM; auxv[15] = (size_t) "x86_64";
    auxv[16] = AT_SECURE;   auxv[17] = 0;
    auxv[18] = AT_UID;      auxv[19] = 0;
    auxv[20] = AT_RANDOM;   auxv[21] = (size_t) rbuf;
    auxv[22] = AT_NULL;     auxv[23] = 0;


    return auxv;
}

void __init_libc(char **envp, char *pn, enclave_config_t *encl)
{
    size_t i, *auxv, aux[AUX_CNT] = { 0 };
    __environ = envp;
    for (i=0; envp[i]; i++);
    libc.auxv = auxv = init_aux((void *)(envp+i+1), pn);
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

static void exitmain(void) {
    lkl_exit();
}

/* By default, we run two servers:
 * 1. A publicly accessible server accepting and responding to attestation
 * requests.
 * 2. A Wireguard-protected server accepting and responding to both attestation
 * and application run requests.
 *
 * If SGXLKL_REMOTE_CMD_ETH0 is set to 1  and we are not in release-mode, the
 * public-facing server accepts application-specific requests too.
 */
static void run_cmd_servers(sgxlkl_app_config_t *app_config, enclave_config_t *encl) {
    struct lthread *lt;

/* In RELEASE mode we always have separate attest-only (public) and cmd
 * servers (behind Wireguard VPN).
 *
 * Fail early: If we expect to receive remote config through the Wireguard
 * interface but no peers have been specified, fail.
 */
#ifdef SGXLKL_RELEASE
    int eth0_cmd = 0;
    if (encl->wg.num_peers != 1)
        sgxlkl_fail("Exactly one Wireguard peer needs to be specified in order to provide application run configuration remotely.\n");
#else
    int eth0_cmd = encl->remote_cmd_eth0;
    if (!eth0_cmd && encl->remote_config && encl->wg.num_peers == 0)
        sgxlkl_fail("At least one Wireguard peer needs to be specified in order to provide application run configuration remotely.\n");
#endif

    // Start attest-only server.

    // Will be free'd within enclave_cmd_server_run
    struct cmd_server_config *attest_srv_conf = malloc(sizeof(*attest_srv_conf));
    memset(attest_srv_conf, 0, sizeof(*attest_srv_conf));
    attest_srv_conf->attest_only = 1;
#ifdef SGXLKL_HW
    attest_srv_conf->att_info = encl->att_info;
#endif
    attest_srv_conf->addr.sin_family = AF_INET;
    attest_srv_conf->addr.sin_port = htons(encl->remote_attest_port);
    attest_srv_conf->addr.sin_addr = encl->net_ip4;

    SGXLKL_VERBOSE("Starting attestation server, listening on %s:%u...\n",
                   inet_ntoa(attest_srv_conf->addr.sin_addr),
                   encl->remote_attest_port);
    if (lthread_create(&lt, NULL, enclave_cmd_server_run, attest_srv_conf) == -1)
        sgxlkl_fail("Failed to created attestation server thread");

    // Warn here and return in non-release mode if we can't provide remote
    // control interface.
    if (!eth0_cmd && encl->wg.num_peers < 1) {
        SGXLKL_VERBOSE("No Wireguard peers specified. Remote control will be unavailable.\n");
        return;
    }

    // Start command/control server

    // Will be free'd within enclave_cmd_server_run
    struct cmd_server_config *cmd_srv_conf = malloc(sizeof(*cmd_srv_conf));
    memset(cmd_srv_conf, 0, sizeof(*cmd_srv_conf));
#ifdef SGXLKL_HW
    cmd_srv_conf->att_info = encl->att_info;
#endif
    cmd_srv_conf->app_config = app_config;
    cmd_srv_conf->addr.sin_family = AF_INET;
    cmd_srv_conf->addr.sin_port = htons(encl->remote_cmd_port);
    cmd_srv_conf->addr.sin_addr = eth0_cmd ? encl->net_ip4 : encl->wg.ip;

    pthread_mutex_t run_mtx;
    pthread_cond_t run_cv;
    if (app_config) {
        int init_ret;
        if ((init_ret = pthread_cond_init(&run_cv, NULL)) ||
            (init_ret = pthread_mutex_init(&run_mtx, NULL)) ||
            (init_ret = pthread_mutex_lock(&run_mtx))) {
            fprintf(stderr, "Could not setup condition variable: %s.\n", strerror(init_ret));
            exit(EXIT_FAILURE);
        }

        cmd_srv_conf->run_mtx = &run_mtx;
        cmd_srv_conf->run_cv = &run_cv;
    }

    SGXLKL_VERBOSE("Starting remote control server, listening on %s:%u...\n",
                   inet_ntoa(cmd_srv_conf->addr.sin_addr),
                   encl->remote_cmd_port);
    if (lthread_create(&lt, NULL, enclave_cmd_server_run, cmd_srv_conf) == -1) {
        exit(EXIT_FAILURE);
    }

    // If we are requested to, wait for remote party to send run configuration
    // to continue
    if (app_config) {
        if (sgxlkl_verbose)
            SGXLKL_VERBOSE("Waiting for application run request...\n");
        pthread_cond_wait(&run_cv, &run_mtx);
        __environ = app_config->envp;
    }

#ifdef SGXLKL_HW
    enclave_config_free(encl);
#endif
}

static int __libc_state = 0;
static int startmain(enclave_config_t *encl) {
    // Disable kernel outputs for normal runs
    sgxlkl_verbose = encl->verbose;
    if (!encl->kernel_verbose) {
        sgxlkl_host_ops.print = NULL;
        lkl_host_ops.print = NULL;
    }

#ifdef SGXLKL_HW
    if (sgxlkl_verbose) {
        SGXLKL_VERBOSE("Maximum enclave threads (TCS): %d\n", get_enclave_parms()->tcsn);
    }
#endif

    __libc_start_init();
    a_barrier();
    __libc_state = 2;

#ifndef SGXLKL_HW
    sim_exit_handler = encl->sim_exit_handler;
#endif

    int res = atexit(exitmain);
    if (res != 0)
        fprintf(stderr, "WARN: unable to register exit handler, code %d\n", res);

    // Setup LKL (hd, net, memory) and start kernel

    // SGX-LKL lthreads inherit names from their parent. Set this to "kernel"
    // temporarily to be able to identify LKL kernel threads.
    lthread_set_funcname(lthread_self(), "kernel");
    lkl_start_init(encl);
    lthread_set_funcname(lthread_self(), "sgx-lkl-init");

    // Get WG public key
    wg_device *wg_dev;
    if (wg_get_device(&wg_dev, "wg0"))
        sgxlkl_fail("Failed to locate Wireguard interface 'wg0'.\n");

    if (sgxlkl_verbose) {
        wg_key_b64_string key;
        wg_key_to_base64(key, wg_dev->public_key);
        sgxlkl_info("wg0 has public key %s\n", key);
#ifdef SGXLKL_HW
        sgxlkl_info("Enclave report nonce: %lu\n", encl->report_nonce);
#endif
    }

    // Create enclave report if requested
#ifdef SGXLKL_HW
    if (encl->report) {
        struct sgxlkl_report_data data = {0};
        memcpy(&data.wg_public_key, wg_dev->public_key, sizeof(data.wg_public_key));
        data.nonce = encl->report_nonce;

        enclave_report(encl->quote_target_info, (sgx_report_data_t*) &data, encl->report);
        leave_enclave(SGXLKL_EXIT_REPORT, (uint64_t) encl->report);

        // encl->att_info is pointer to untrusted outside memory
        // Copy attestation info into enclave
        attestation_info_t *att_info;
        if (!(att_info = malloc(sizeof(*att_info))))
            sgxlkl_fail("Failed to copy attestation into enclave: %s\n", strerror(errno));
        *att_info = *encl->att_info;
        // Ensure quote and IAS report pointers point to outside memory
        if (att_info->quote && in_enclave_range(att_info->quote, sizeof(*att_info->quote)))
            sgxlkl_fail("iAttestation error: Quote points into enclave memory. Exiting.\n");
        if (att_info->ias_report && in_enclave_range(att_info->ias_report, sizeof(*att_info->ias_report)))
            sgxlkl_fail("iAttestation error: IAS report points into enclave memory. Exiting.\n");
        encl->att_info = att_info;
    }
#endif

    // Start control server and initialize app config (argc, argv, envp).
    sgxlkl_app_config_t app_config = {};
#ifndef SGXLKL_RELEASE
    if (encl->remote_config) {
# else
    // In Release mode the app configuration has to be provided remotely.
    if(1) {
#endif
        if (!encl->net_fd) {
            // No network, no point in continuing.
            sgxlkl_fail("Remote configuration expected, but no networking available.\n");
        }

        // Start cmd/control servers and wait for application config
        run_cmd_servers(&app_config, encl);
    } else {
        if (encl->app_config) {
            char *err_desc;
            if (parse_sgxlkl_app_config_from_str(encl->app_config, &app_config, &err_desc))
                sgxlkl_fail("Failed to parse application configuration: %s.\n", err_desc);
        } else {
            app_config.argc = encl->argc;
            app_config.argv = encl->argv;
            app_config.envp = encl->argv + encl->argc + 1;
            app_config.cwd = encl->cwd;
        }

        if (encl->net_fd)
            run_cmd_servers(NULL, encl);
    }

    // Disk config has been set through app config
    // Merge host-provided disk info (fd, capacity, mmap)
    if (app_config.disks) {
        for (int i = 0; i < app_config.num_disks; i++) {
            enclave_disk_config_t *disk = &app_config.disks[i];
            // Initialize with fd -1 to make sure we don't try to mount disks for
            // which no fd has been provided by the host.
            disk->fd = -1;
            for (int j = 0; j < encl->num_disks; j++) {
                enclave_disk_config_t *disk_untrusted = &encl->disks[j];
                if (!strcmp(disk->mnt, disk_untrusted->mnt)) {
                    disk->fd = disk_untrusted->fd;
                    disk->capacity = disk_untrusted->capacity;
                    disk->mmap = disk_untrusted->mmap;
                    disk->wait_on_io = encl->wait_on_io_host_calls;
                    break;
                }
            }
            // TODO Propagate error (message) back to remote user.
            if (disk->fd == -1)
                sgxlkl_warn("Disk image for mount point '%s' has not been provided by host.\n", disk->mnt);
        }
    } else {
        app_config.num_disks = encl->num_disks;
        app_config.disks = encl->disks;
    }

    // Mount disks
    lkl_mount_disks(app_config.disks, app_config.num_disks, app_config.cwd);

    // Add Wireguard peers
    if (wg_dev) {
        wgu_add_peers(wg_dev, app_config.peers, app_config.num_peers, 1);
    } else if (app_config.num_peers) {
        sgxlkl_warn("Failed to add wireguard peers: No device 'wg0' found.\n");
    }
    if (app_config.num_peers && sgxlkl_verbose)
        wgu_list_devices();

    // Launch stage 3 dynamic linker, passing in top of stack to overwrite.
    // The dynamic linker will then load the application proper; here goes!
    __dls3(&app_config, __builtin_frame_address(0));
}

int __libc_init_enclave(int argc, char **argv, enclave_config_t *_encl)
{
    struct lthread *lt;
    char **envp = argv + argc + 1;

#ifdef SGXLKL_HW
    void *heap = (void *)get_enclave_parms()->heap;
    size_t heap_size = get_enclave_parms()->heap_size;
#else
    void *heap = _encl->heap;
    size_t heap_size = _encl->heapsize;
#endif

#ifndef SGXLKL_HW
    int c;
    /* 1 - initialization in progress, 2 - initialized */
    while ((c = a_cas(&__libc_state, 0, 1)) == 1) {a_spin();}
    if (c == 2) {
        __init_tls();
        _lthread_sched_init(_encl->stacksize);
        lthread_run();
        return 0;
    }
#endif
    enclave_mman_init(heap, heap_size / PAGESIZE, _encl->mmap_files);

#ifdef SGXLKL_HW
    // Create an in-memory copy of the enclave config (to prevent potential
    // TOCTOU vulnerabilities and check for out-of-range pointers (i.e.
    // pointers into enclave memory).
    //
    // enclave_copy_and_check requires malloc which requires the memory
    // management to have been set up. Call after enclave_mman_init.
    enclave_config_t *encl = enclave_config_copy_and_check(_encl);
#else
    enclave_config_t *encl = _encl;
#endif

    libc.vvar_base = encl->vvar;
    libc.user_tls_enabled = encl->mode == SGXLKL_HW_MODE ? encl->fsgsbase : 1;

    init_sysconf(encl->sysconf_nproc_conf, encl->sysconf_nproc_onln);
    init_clock_res(encl->clock_res);

    size_t max_lthreads = encl->max_user_threads * sizeof(*__scheduler_queue.buffer);
    max_lthreads = next_pow2(max_lthreads);

    newmpmcq(&__scheduler_queue, max_lthreads, 0);

    __syscall_queue = encl->syscallq;
    __return_queue = encl->returnq;

    hostsyscallclient_init(encl);

    __init_libc(envp, argv[0], encl);
    __init_tls();

     size_t futex_wake_spins = encl->vvar ? 1 : 500;
     size_t espins = encl->espins;
     size_t esleep = encl->esleep;
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

    SGXLKL_VERBOSE("Calling application main\n");

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

    size_t base = (size_t) get_enclave_parms()->base
                         + get_enclave_parms()->heap_size;

    _dlstart_c(base);

    __libc_init_enclave(encl->argc, encl->argv, encl);
    return 0;
}

void __sgx_lkl_entry(uint64_t call_id, void* arg) {
    enclave_config_t* encl = (enclave_config_t*)arg;
    switch (call_id) {
        case SGXLKL_ENTER_THREAD_CREATE: {
            int c;
            /* 1 - initialization in progress, 2 - initialized */
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
