/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "confine.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#elif defined(__FreeBSD__)
#include <sys/capsicum.h>
#endif

#include "gzip.h"
#include "store.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/*
 * Two kinds of build that have to write where nothing confined may:
 *
 *   coverage    each process writes its counts as it exits, beneath the
 *               directory RS_COVERAGE_DIR names (scripts/coverage.sh), which
 *               is then writable too
 *   sanitizers  LeakSanitizer stops the process's threads with ptrace and
 *               reads /proc as it exits, and logs where ASAN_OPTIONS says:
 *               on Linux, such a build is not confined at all
 *
 * Neither is a build anything is served with.
 */
#if defined(__SANITIZE_ADDRESS__)
#define RS_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define RS_SANITIZED 1
#endif
#endif

/* Whatever a later call would read the first time it is made -- the time
 * zone's file, for one -- read now, while every file can be. */
static void warm(void)
{
    time_t    now = time(NULL);
    struct tm tm;

    tzset();
    (void)gmtime_r(&now, &tm);
    (void)localtime_r(&now, &tm);
    (void)rs_gzip_path();
}

#if defined(__OpenBSD__)

/* ------------------------------------------------------------------------ */
/* OpenBSD: pledge and unveil                                               */
/* ------------------------------------------------------------------------ */

const char *rs_confine_how(void)
{
    return "pledge, unveil";
}

static bool unveiled(const char *path, const char *how, struct rs_buf *why)
{
    if (unveil(path, how) != 0)
    {
        rs_buf_addf(why, "unveil %s: %s", path, strerror(errno));
        return false;
    }
    return true;
}

bool rs_confine(enum rs_confine_role role, const char *repository, const char *staging,
                struct rs_buf *why)
{
    bool committer = role == RS_CONFINE_COMMITTER;

    warm();
    if (!unveiled(repository, committer ? "rwc" : "r", why) ||
        (staging && !unveiled(staging, "rwc", why)))
    {
        return false;
    }
    /* The kernel finds a program's run-time linker by path as it starts it,
     * under the unveil still in force then; gzip is linked dynamically. */
    if (committer && rs_gzip_path() &&
        (!unveiled(rs_gzip_path(), "rx", why) || !unveiled("/usr/libexec/ld.so", "r", why)))
    {
        return false;
    }
#ifdef RS_COVERAGE_DIR
    if (!unveiled(RS_COVERAGE_DIR, "rwc", why))
    {
        return false;
    }
#endif
    if (unveil(NULL, NULL) != 0)
    {
        rs_buf_addf(why, "unveil: %s", strerror(errno));
        return false;
    }
    /* gzip's own promises are its own: it pledges itself. */
    if (pledge(committer ? "stdio rpath wpath cpath fattr proc exec" : "stdio rpath wpath cpath",
               NULL) != 0)
    {
        rs_buf_addf(why, "pledge: %s", strerror(errno));
        return false;
    }
    return true;
}

#elif defined(__FreeBSD__)

/* ------------------------------------------------------------------------ */
/* FreeBSD: Capsicum                                                        */
/* ------------------------------------------------------------------------ */

const char *rs_confine_how(void)
{
    return "capsicum";
}

bool rs_confine(enum rs_confine_role role, const char *repository, const char *staging,
                struct rs_buf *why)
{
    const char *dirs[2];

    /* A program is never run in capability mode, and the committer runs
     * gzip: it is what it is. */
    if (role == RS_CONFINE_COMMITTER)
    {
        return true;
    }
    warm();
    dirs[0] = repository;
    dirs[1] = staging;
    if (!rs_store_confine(dirs, staging ? 2 : 1, why))
    {
        return false;
    }
    if (cap_enter() != 0 && errno != ENOSYS)
    {
        rs_buf_addf(why, "cap_enter: %s", strerror(errno));
        return false;
    }
    return true;
}

#elif defined(__linux__)

/* ------------------------------------------------------------------------ */
/* Linux: Landlock and seccomp                                              */
/* ------------------------------------------------------------------------ */
/*
 * Both by their system calls and the kernel's own numbers for them, not by
 * <linux/landlock.h> and <linux/seccomp.h>: the ABI is fixed, and a system
 * whose headers are older than its kernel still confines.
 */

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

#define LL_CREATE_RULESET_VERSION 1u
#define LL_RULE_PATH_BENEATH      1

#define LL_FS_EXECUTE     (1ull << 0)
#define LL_FS_WRITE_FILE  (1ull << 1)
#define LL_FS_READ_FILE   (1ull << 2)
#define LL_FS_READ_DIR    (1ull << 3)
#define LL_FS_REMOVE_DIR  (1ull << 4)
#define LL_FS_REMOVE_FILE (1ull << 5)
#define LL_FS_MAKE_CHAR   (1ull << 6)
#define LL_FS_MAKE_DIR    (1ull << 7)
#define LL_FS_MAKE_REG    (1ull << 8)
#define LL_FS_MAKE_SOCK   (1ull << 9)
#define LL_FS_MAKE_FIFO   (1ull << 10)
#define LL_FS_MAKE_BLOCK  (1ull << 11)
#define LL_FS_MAKE_SYM    (1ull << 12)
#define LL_FS_REFER       (1ull << 13)   /* ABI 2 */
#define LL_FS_TRUNCATE    (1ull << 14)   /* ABI 3 */
#define LL_FS_IOCTL_DEV   (1ull << 15)   /* ABI 5 */
#define LL_NET_BIND_TCP    (1ull << 0)   /* ABI 4 */
#define LL_NET_CONNECT_TCP (1ull << 1)
#define LL_SCOPE_ABSTRACT_UNIX (1ull << 0)  /* ABI 6 */
#define LL_SCOPE_SIGNAL        (1ull << 1)

/* What can be granted on a file, not a directory. */
#define LL_FILE_RIGHTS (LL_FS_EXECUTE | LL_FS_WRITE_FILE | LL_FS_READ_FILE | LL_FS_TRUNCATE | \
                        LL_FS_IOCTL_DEV)

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct ll_path_beneath {
    uint64_t allowed_access;
    int32_t  parent_fd;
} __attribute__((packed));

/* Landlock's ABI here: 0 for none. */
static int landlock_abi(void)
{
    long v = syscall(SYS_landlock_create_ruleset, NULL, (size_t)0, LL_CREATE_RULESET_VERSION);

    return v > 0 ? (int)v : 0;
}

/* Every right ABI `abi` has over files. */
static uint64_t fs_rights(int abi)
{
    uint64_t all = (LL_FS_MAKE_SYM << 1) - 1;

    if (abi >= 2)
    {
        all |= LL_FS_REFER;
    }
    if (abi >= 3)
    {
        all |= LL_FS_TRUNCATE;
    }
    if (abi >= 5)
    {
        all |= LL_FS_IOCTL_DEV;
    }
    return all;
}

/* `path` allowed `rights` (those of them ABI `handled` has) in `ruleset`: a
 * path that is not there is passed over, if `optional`. */
static bool allow(int ruleset, const char *path, uint64_t rights, uint64_t handled, bool optional,
                  struct rs_buf *why)
{
    struct ll_path_beneath rule;
    struct stat            st;
    int                    fd = open(path, O_PATH | O_CLOEXEC);
    long                   rc;

    if (fd < 0)
    {
        if (optional && (errno == ENOENT || errno == ENOTDIR))
        {
            return true;
        }
        rs_buf_addf(why, "landlock: %s: %s", path, strerror(errno));
        return false;
    }
    memset(&rule, 0, sizeof(rule));
    rule.allowed_access = rights & handled;
    if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
    {
        rule.allowed_access &= LL_FILE_RIGHTS;
    }
    rule.parent_fd = fd;
    rc = syscall(SYS_landlock_add_rule, ruleset, LL_RULE_PATH_BENEATH, &rule, 0u);
    (void)close(fd);
    if (rc != 0)
    {
        rs_buf_addf(why, "landlock: %s: %s", path, strerror(errno));
        return false;
    }
    return true;
}

/* Landlock, as `role` says: true where the kernel has none. */
static bool landlock(enum rs_confine_role role, const char *repository, const char *staging,
                     struct rs_buf *why)
{
    static const char *const system_dirs[] = { "/usr", "/bin", "/lib", "/lib64", "/lib32",
                                               "/libx32", "/etc/ld.so.cache",
                                               "/etc/ld.so.preload" };
    const uint64_t           read = LL_FS_READ_FILE | LL_FS_READ_DIR;
    const uint64_t write = read | LL_FS_WRITE_FILE | LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR |
                           LL_FS_MAKE_DIR | LL_FS_MAKE_REG | LL_FS_REFER | LL_FS_TRUNCATE;
    struct ll_ruleset_attr attr;
    int                    abi = landlock_abi();
    size_t                 size;
    size_t                 i;
    int                    ruleset;
    bool                   committer = role == RS_CONFINE_COMMITTER;
    bool                   ok;

    if (abi == 0)
    {
        return true;
    }
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = fs_rights(abi);
    size = offsetof(struct ll_ruleset_attr, handled_access_net);
    if (abi >= 4)
    {
        attr.handled_access_net = LL_NET_BIND_TCP | LL_NET_CONNECT_TCP;
        size = offsetof(struct ll_ruleset_attr, scoped);
    }
    if (abi >= 6)
    {
        attr.scoped = LL_SCOPE_ABSTRACT_UNIX | LL_SCOPE_SIGNAL;
        size = sizeof(attr);
    }
    ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr, size, 0u);
    if (ruleset < 0)
    {
        rs_buf_addf(why, "landlock: %s", strerror(errno));
        return false;
    }
    ok = allow(ruleset, repository, committer ? write : read, attr.handled_access_fs, false,
               why) &&
         (!staging || allow(ruleset, staging, write, attr.handled_access_fs, false, why));
#ifdef RS_COVERAGE_DIR
    ok = ok && allow(ruleset, RS_COVERAGE_DIR, write, attr.handled_access_fs, true, why);
#endif
    for (i = 0; ok && committer && i < sizeof(system_dirs) / sizeof(system_dirs[0]); i++)
    {
        ok = allow(ruleset, system_dirs[i], read | LL_FS_EXECUTE, attr.handled_access_fs, true,
                   why);
    }
    if (ok && syscall(SYS_landlock_restrict_self, ruleset, 0u) != 0)
    {
        rs_buf_addf(why, "landlock: %s", strerror(errno));
        ok = false;
    }
    (void)close(ruleset);
    return ok;
}

/* The filter's language and seccomp's (<linux/filter.h>, <linux/seccomp.h>). */
struct bpf_insn {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct bpf_prog {
    unsigned short   len;
    struct bpf_insn *filter;
};

#define BPF_LD_W_ABS  0x20
#define BPF_JEQ_K     0x15
#define BPF_JGE_K     0x35
#define BPF_RET_K     0x06
#define SECCOMP_ALLOW 0x7fff0000u
#define SECCOMP_ERRNO 0x00050000u
#define SECCOMP_FILTER_MODE 2
#define DATA_NR   0     /* offsetof(struct seccomp_data, nr) */
#define DATA_ARCH 4     /* offsetof(struct seccomp_data, arch) */

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

/* The audit architecture of this build, as the kernel gives it a filter: 0
 * for one this file does not know, which is not filtered. */
#define ARCH_64 0x80000000u
#define ARCH_LE 0x40000000u
#if defined(__x86_64__) && !defined(__ILP32__)
#define NATIVE_ARCH (62u | ARCH_64 | ARCH_LE)
#elif defined(__i386__)
#define NATIVE_ARCH (3u | ARCH_LE)
#elif defined(__aarch64__) && !defined(__AARCH64EB__)
#define NATIVE_ARCH (183u | ARCH_64 | ARCH_LE)
#elif defined(__arm__) && !defined(__ARMEB__)
#define NATIVE_ARCH (40u | ARCH_LE)
#elif defined(__s390x__)
#define NATIVE_ARCH (22u | ARCH_64)
#elif defined(__powerpc64__) && defined(__BYTE_ORDER__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NATIVE_ARCH (21u | ARCH_64 | ARCH_LE)
#elif defined(__powerpc64__)
#define NATIVE_ARCH (21u | ARCH_64)
#elif defined(__riscv) && __riscv_xlen == 64
#define NATIVE_ARCH (243u | ARCH_64 | ARCH_LE)
#elif defined(__loongarch64)
#define NATIVE_ARCH (258u | ARCH_64 | ARCH_LE)
#else
#define NATIVE_ARCH 0u
#endif

/* What neither process has any use for, refused as EPERM. */
static const long denied[] = {
#ifdef SYS_socket
    SYS_socket,
#endif
#ifdef SYS_socketpair
    SYS_socketpair,
#endif
#ifdef SYS_connect
    SYS_connect,
#endif
#ifdef SYS_bind
    SYS_bind,
#endif
#ifdef SYS_listen
    SYS_listen,
#endif
#ifdef SYS_accept
    SYS_accept,
#endif
#ifdef SYS_accept4
    SYS_accept4,
#endif
#ifdef SYS_socketcall
    SYS_socketcall,
#endif
#ifdef SYS_ptrace
    SYS_ptrace,
#endif
#ifdef SYS_process_vm_readv
    SYS_process_vm_readv,
#endif
#ifdef SYS_process_vm_writev
    SYS_process_vm_writev,
#endif
#ifdef SYS_mount
    SYS_mount,
#endif
#ifdef SYS_umount2
    SYS_umount2,
#endif
#ifdef SYS_umount
    SYS_umount,
#endif
#ifdef SYS_pivot_root
    SYS_pivot_root,
#endif
#ifdef SYS_chroot
    SYS_chroot,
#endif
#ifdef SYS_swapon
    SYS_swapon,
#endif
#ifdef SYS_swapoff
    SYS_swapoff,
#endif
#ifdef SYS_reboot
    SYS_reboot,
#endif
#ifdef SYS_kexec_load
    SYS_kexec_load,
#endif
#ifdef SYS_kexec_file_load
    SYS_kexec_file_load,
#endif
#ifdef SYS_init_module
    SYS_init_module,
#endif
#ifdef SYS_finit_module
    SYS_finit_module,
#endif
#ifdef SYS_delete_module
    SYS_delete_module,
#endif
#ifdef SYS_bpf
    SYS_bpf,
#endif
#ifdef SYS_perf_event_open
    SYS_perf_event_open,
#endif
#ifdef SYS_unshare
    SYS_unshare,
#endif
#ifdef SYS_setns
    SYS_setns,
#endif
#ifdef SYS_keyctl
    SYS_keyctl,
#endif
#ifdef SYS_add_key
    SYS_add_key,
#endif
#ifdef SYS_request_key
    SYS_request_key,
#endif
#ifdef SYS_userfaultfd
    SYS_userfaultfd,
#endif
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup,
#endif
#ifdef SYS_io_uring_enter
    SYS_io_uring_enter,
#endif
#ifdef SYS_io_uring_register
    SYS_io_uring_register,
#endif
#ifdef SYS_open_by_handle_at
    SYS_open_by_handle_at,
#endif
#ifdef SYS_name_to_handle_at
    SYS_name_to_handle_at,
#endif
#ifdef SYS_kcmp
    SYS_kcmp,
#endif
#ifdef SYS_quotactl
    SYS_quotactl,
#endif
#ifdef SYS_acct
    SYS_acct,
#endif
#ifdef SYS_settimeofday
    SYS_settimeofday,
#endif
#ifdef SYS_clock_settime
    SYS_clock_settime,
#endif
#ifdef SYS_adjtimex
    SYS_adjtimex,
#endif
#ifdef SYS_clock_adjtime
    SYS_clock_adjtime,
#endif
#ifdef SYS_iopl
    SYS_iopl,
#endif
#ifdef SYS_ioperm
    SYS_ioperm,
#endif
#ifdef SYS_fanotify_init
    SYS_fanotify_init,
#endif
#ifdef SYS_move_mount
    SYS_move_mount,
#endif
#ifdef SYS_fsopen
    SYS_fsopen,
#endif
#ifdef SYS_fsmount
    SYS_fsmount,
#endif
#ifdef SYS_open_tree
    SYS_open_tree,
#endif
#ifdef SYS_fspick
    SYS_fspick,
#endif
#ifdef SYS_mount_setattr
    SYS_mount_setattr,
#endif
#ifdef SYS_mknod
    SYS_mknod,
#endif
#ifdef SYS_mknodat
    SYS_mknodat,
#endif
#ifdef SYS_personality
    SYS_personality,
#endif
#ifdef SYS_uselib
    SYS_uselib,
#endif
#ifdef SYS_vhangup
    SYS_vhangup,
#endif
#ifdef SYS_syslog
    SYS_syslog,
#endif
    -1
};

/* And what the connection, which runs nothing, does not have either. */
static const long denied_running[] = {
#ifdef SYS_execve
    SYS_execve,
#endif
#ifdef SYS_execveat
    SYS_execveat,
#endif
    -1
};

#define FILTER_MAX 128

/* The seccomp filter, as `role` says: true where the kernel has none, or
 * this architecture is not one this file knows. */
static bool seccomp_filter(enum rs_confine_role role, struct rs_buf *why)
{
    struct bpf_insn f[FILTER_MAX];
    struct bpf_prog prog;
    size_t          n = 0;
    size_t          deny;
    size_t          i;
    size_t          total = 0;

    if (NATIVE_ARCH == 0u)
    {
        return true;
    }
    for (i = 0; denied[i] >= 0; i++)
    {
        total++;
    }
    for (i = 0; role == RS_CONFINE_CONNECTION && denied_running[i] >= 0; i++)
    {
        total++;
    }
    /* arch load and check, nr load, the x32 check, each call, allow, deny */
    deny = 4 + total + 1;
    if (deny + 1 > FILTER_MAX)
    {
        rs_buf_addstr(why, "seccomp: the filter is too long");
        return false;
    }
    f[n++] = (struct bpf_insn){ BPF_LD_W_ABS, 0, 0, DATA_ARCH };
    /* Another architecture's calls -- i386's, on x86_64 -- are none of them. */
    f[n] = (struct bpf_insn){ BPF_JEQ_K, 0, (uint8_t)(deny - n - 1), NATIVE_ARCH };
    n++;
    f[n++] = (struct bpf_insn){ BPF_LD_W_ABS, 0, 0, DATA_NR };
    /* x32's calls, on x86_64, have their own numbers; elsewhere this bit
     * is a number no call has. */
    f[n] = (struct bpf_insn){ BPF_JGE_K, (uint8_t)(deny - n - 1), 0, 0x40000000u };
    n++;
    for (i = 0; denied[i] >= 0; i++)
    {
        f[n] = (struct bpf_insn){ BPF_JEQ_K, (uint8_t)(deny - n - 1), 0, (uint32_t)denied[i] };
        n++;
    }
    for (i = 0; role == RS_CONFINE_CONNECTION && denied_running[i] >= 0; i++)
    {
        f[n] = (struct bpf_insn){ BPF_JEQ_K, (uint8_t)(deny - n - 1), 0,
                                  (uint32_t)denied_running[i] };
        n++;
    }
    f[n++] = (struct bpf_insn){ BPF_RET_K, 0, 0, SECCOMP_ALLOW };
    f[n++] = (struct bpf_insn){ BPF_RET_K, 0, 0, SECCOMP_ERRNO | (uint32_t)EPERM };
    prog.len = (unsigned short)n;
    prog.filter = f;
    if (prctl(PR_SET_SECCOMP, SECCOMP_FILTER_MODE, &prog, 0, 0) != 0)
    {
        /* A kernel built without seccomp's filters. */
        if (errno == EINVAL)
        {
            return true;
        }
        rs_buf_addf(why, "seccomp: %s", strerror(errno));
        return false;
    }
    return true;
}

const char *rs_confine_how(void)
{
    static char how[64];
    int         abi = landlock_abi();

#ifdef RS_SANITIZED
    (void)abi;
    return "none (a sanitizer's build)";
#endif
#if NATIVE_ARCH
    {
        bool seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0) >= 0;

        if (abi > 0)
        {
            (void)snprintf(how, sizeof(how), "landlock (ABI %d)%s", abi,
                           seccomp ? ", seccomp" : "");
        } else
        {
            (void)snprintf(how, sizeof(how), "%s", seccomp ? "seccomp" : "none");
        }
    }
#else
    /* An architecture whose calls this file does not know: no filter. */
    if (abi > 0)
    {
        (void)snprintf(how, sizeof(how), "landlock (ABI %d)", abi);
    } else
    {
        (void)snprintf(how, sizeof(how), "none");
    }
#endif
    return how;
}

bool rs_confine(enum rs_confine_role role, const char *repository, const char *staging,
                struct rs_buf *why)
{
    warm();
#ifdef RS_SANITIZED
    (void)role;
    (void)repository;
    (void)staging;
    (void)why;
    return true;
#endif
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        rs_buf_addf(why, "no_new_privs: %s", strerror(errno));
        return false;
    }
    return landlock(role, repository, staging, why) && seccomp_filter(role, why);
}

#else

/* ------------------------------------------------------------------------ */
/* Elsewhere: nothing to confine with                                       */
/* ------------------------------------------------------------------------ */

const char *rs_confine_how(void)
{
    return "none";
}

bool rs_confine(enum rs_confine_role role, const char *repository, const char *staging,
                struct rs_buf *why)
{
    (void)role;
    (void)repository;
    (void)staging;
    (void)why;
    warm();
    return true;
}

#endif
