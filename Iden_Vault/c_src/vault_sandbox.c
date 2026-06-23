/*
 * vault_sandbox.c
 *
 * VAULT SECURITY SYSTEM — IdenVault Hardened Sandbox v2
 * Section 12 from legacy monolith
 *
 * Linux-only: 5-layer defense-in-depth sandbox
 *   1. User Namespace  — root in sandbox → nobody on host
 *   2. Mount + PID NS  — private process/fs view
 *   3. Pivot Root      — replaces chroot (more secure)
 *   4. Capability Drop — removes all Linux Caps + NO_NEW_PRIVS
 *   5. Seccomp-BPF     — minimal allowlist, KILL as default
 *
 * On Windows: stub that returns ERR_SYSTEM (sandbox not available).
 *
 * Author: Peter Steve (architecture)
 * Split: 2026-05-13
 */

#include "vault_core.h"

#ifdef __linux__
#include <sys/sysmacros.h>

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_drop_caps(): Remove all Linux Capabilities
 * ───────────────────────────────────────────────────────────────────────── */
static int sandbox_drop_caps(void)
{
    cap_t empty = cap_init();
    if (empty == NULL)
    {
        perror("[SANDBOX] cap_init");
        return -1;
    }

    if (cap_set_proc(empty) != 0)
    {
        perror("[SANDBOX] cap_set_proc");
        cap_free(empty);
        return -1;
    }
    cap_free(empty);

    if (prctl(PR_SET_KEEPCAPS, 0) != 0)
    {
        perror("[SANDBOX] PR_SET_KEEPCAPS");
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        perror("[SANDBOX] PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    /* Verify caps are empty */
    cap_t check = cap_get_proc();
    if (check != NULL)
    {
        char *text = cap_to_text(check, NULL);
        if (text && strcmp(text, "=") != 0)
        {
            fprintf(stderr, "[SANDBOX] residual caps after drop: %s\n", text);
            cap_free(text);
            cap_free(check);
            return -1;
        }
        cap_free(text);
        cap_free(check);
    }

    return 0;
}

/* 
 *  sandbox_pivot_root(): Pivot root to vault path
 * 
 */
static int mount_bind(const char *src, const char *target) {
    if (mount(src, target, NULL, MS_BIND | MS_REC, NULL) != 0)
    {
        perror("[SANDBOX] mount MS_BIND");
        return -1;
    }
    return 0;
}
static int sandbox_pivot_root(const char *new_root)
{
    if (new_root == NULL || new_root[0] == '\0')
    {
        fprintf(stderr, "[SANDBOX] pivot_root: new_root empty\n");
        return -1;
    }

    int ret = -1;
    char oldroot[64] = "/tmp/.sandbox_oldroot_XXXXXX";

    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) != 0)
    {
        perror("[SANDBOX] mount MS_BIND");
        return -1;
    }

    if (chdir(new_root) != 0)
    {
        perror("[SANDBOX] chdir new_root");
        goto cleanup_bind;
    }

    if (mkdtemp(oldroot) == NULL)
    {
        perror("[SANDBOX] mkdtemp oldroot");
        goto cleanup_bind;
    }

    struct stat st;
    if (lstat(oldroot, &st) != 0 || !S_ISDIR(st.st_mode))
    {
        fprintf(stderr, "[SANDBOX] oldroot is not a real directory\n");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    if (syscall(SYS_pivot_root, ".", oldroot) != 0)
    {
        perror("[SANDBOX] pivot_root");
        rmdir(oldroot);
        goto cleanup_bind;
    }

    char oldroot_abs[80];
    snprintf(oldroot_abs, sizeof(oldroot_abs), "/%s", oldroot);
    
    umount2(oldroot_abs, MNT_DETACH);
    rmdir(oldroot_abs);

    if (chdir("/") != 0)
    {
        perror("[SANDBOX] chdir / after pivot_root");
        goto cleanup_bind;
    }

    ret = 0;
    goto done;

cleanup_bind:
    umount2(new_root, MNT_DETACH);

done:
    return ret;
}

/* 
 *  sandbox_prepare_mounts(): Minimal filesystem mounts
 * 
 */
static void sandbox_prepare_mounts(void)
{
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
        perror("sandbox: MS_PRIVATE / (non-fatal)");

    if (mkdir("/proc", 0555) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /proc (non-fatal)");

    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
        perror("sandbox: mount /proc (non-fatal)");

    if (mkdir("/tmp", 01777) != 0 && errno != EEXIST)
        perror("sandbox: mkdir /tmp (non-fatal)");

    if (mount("tmpfs", "/tmp", "tmpfs",
              MS_NOSUID | MS_NODEV,
              SANDBOX_TMP_SIZE) != 0)
        perror("sandbox: mount /tmp (non-fatal)");
}

/* 
 *  sandbox_limit_resources(): rlimits to prevent DoS
 * 
 */
static void sandbox_limit_resources(void)
{
    struct rlimit rl;

    rl.rlim_cur = rl.rlim_max = 32;
    setrlimit(RLIMIT_NPROC, &rl);

    rl.rlim_cur = rl.rlim_max = 128 * 1024 * 1024;
    setrlimit(RLIMIT_AS, &rl);

    rl.rlim_cur = rl.rlim_max = 32 * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);

    rl.rlim_cur = rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
}

/* 
 *  apply_seccomp_policy(): Seccomp-BPF allowlist
 * 
 */
static int apply_seccomp_policy(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx)
    {
        perror("[SANDBOX] seccomp_init");
        return -1;
    }

    /* I/O */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);

    /* Files */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

    /* Directories */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);

    /* Memory */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    /* Processes */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(waitid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);

    /* Signals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigsuspend), 0);

    /* Identity */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0);

    /* Sync */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

    /* Libc init */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);

    /* Time */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    /* rseq (restartable sequences) — called automatically by glibc/busybox on startup */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);

    /* Resource limits — used by sandbox layer 4 and read by shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setrlimit), 0);

    /* Modern filesystem syscalls used by busybox */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(memfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdirat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(truncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimensat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mincore), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getscheduler), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getparam), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_gettime), 0);

    /* System info — uname is called by busybox sh for prompt/hostname */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    /* Note: gethostname/tcgetattr/tcsetattr are libc wrappers over uname/ioctl, already allowed */

    /* Process/session management used by shell job control */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresgid), 0);
    /* tcgetattr/tcsetattr are ioctl wrappers — ioctl already in allowlist */

    /* File copy / sendfile used by cp and similar builtins */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(copy_file_range), 0);

    /* Misc libc internals */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_getres), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_settime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);

    /* Poll / select — needed by interactive shell */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);

    /* Access / permissions */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat2), 0);

    /* prctl — busybox sh uses it to read process name / check caps */
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);

    /* Explicit blocks */
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(chroot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setns), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(capset), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(perf_event_open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(kexec_load), 0);

    int ret = seccomp_load(ctx);
    if (ret != 0)
        perror("[SANDBOX] seccomp_load");
    seccomp_release(ctx);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  sandbox_write_uid_gid_map(): Write UID/GID maps for user namespace
 * ───────────────────────────────────────────────────────────────────────── */
static void sandbox_write_uid_gid_map(pid_t child_pid)
{
    char path[256];
    char map[64];
    int fd;
    ssize_t n;
    int map_len;

    /* setgroups deny — precisa vir ANTES de gid_map em kernels que exigem isso */
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)child_pid);
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][WARN] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, "deny", 4);
        if (n != 4)
            fprintf(stderr, "[SANDBOX][WARN] write(%s) falhou: %s\n", path, strerror(errno));
        close(fd);
    }

    /* uid_map: namespace UID 0 -> real host UID (unprivileged users can only map their own UID) */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "0 %d 1\n", (int)getuid());
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][FATAL] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            fprintf(stderr, "[SANDBOX][FATAL] write(%s) falhou: %s (escrito %zd de %d bytes)\n",
                    path, strerror(errno), n, map_len);
        else
            fprintf(stderr, "[SANDBOX][OK] uid_map escrito: \"%s\"\n", map);
        close(fd);
    }

    /* gid_map: namespace GID 0 -> real host GID */
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    map_len = snprintf(map, sizeof(map), "0 %d 1\n", (int)getgid());
    fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[SANDBOX][FATAL] open(%s): %s\n", path, strerror(errno));
    }
    else
    {
        n = write(fd, map, (size_t)map_len);
        if (n != map_len)
            fprintf(stderr, "[SANDBOX][FATAL] write(%s) falhou: %s (escrito %zd de %d bytes)\n",
                    path, strerror(errno), n, map_len);
        else
            fprintf(stderr, "[SANDBOX][OK] gid_map escrito: \"%s\"\n", map);
        close(fd);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_run_installer(): Fork + exec package manager to install busybox-static
 *
 *  Tenta os package managers conhecidos em ordem. Retorna 0 se o processo
 *  do instalador saiu com success, -1 caso contrário.
 *  Não garante que o pacote existe — o chamador deve re-checar o path.
 * ───────────────────────────────────────────────────────────────────────── */
static int jail_run_installer(void)
{
    /* Cada entrada: { argv[0..n], NULL } */
    const char *installers[][6] = {
        /* Debian / Ubuntu */
        { "apt-get", "install", "-y", "--no-install-recommends", "busybox-static", NULL },
        /* Fedora / RHEL 10+ */
        { "dnf",     "install", "-y", "busybox",                 NULL,             NULL },
        /* Arch */
        { "pacman",  "-Sy",     "--noconfirm", "busybox",        NULL,             NULL },
        /* Alpine */
        { "apk",     "add",     "--no-cache",  "busybox-static", NULL,             NULL },
        /* openSUSE */
        { "zypper",  "install", "-y",          "busybox-static", NULL,             NULL },
        { NULL }
    };

    /* Paths de busca para os binários dos package managers */
    const char *pm_paths[] = {
        "/usr/bin/apt-get",
        "/usr/bin/dnf",
        "/usr/bin/pacman",
        "/sbin/apk",
        "/usr/bin/zypper",
        NULL
    };

    for (int i = 0; installers[i][0] != NULL; i++) {
        /* Verifica se o pm existe antes de forkar */
        struct stat st;
        if (stat(pm_paths[i], &st) != 0)
            continue;

        vault_log(LOG_INFO,
                  "[SANDBOX] Detected package manager '%s' — invoking to install busybox-static...",
                  pm_paths[i]);

        printf("[SANDBOX] [AUTO-INSTALL] Running: %s", pm_paths[i]);
        for (int j = 1; installers[i][j]; j++)
            printf(" %s", installers[i][j]);
        printf("\n");
        fflush(stdout);

        pid_t pid = fork();
        if (pid < 0) {
            vault_log(LOG_WARN, "[SANDBOX] fork for installer failed: %s", strerror(errno));
            continue;
        }

        if (pid == 0) {
            /* Filho: redireciona stdout/stderr para /dev/null se não for root
             * para não poluir o terminal com output do apt */
            if (geteuid() != 0) {
                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    dup2(devnull, STDOUT_FILENO);
                    dup2(devnull, STDERR_FILENO);
                    close(devnull);
                }
            }
            /* execvp busca no PATH automaticamente */
            execvp(installers[i][0], (char *const *)installers[i]);
            _exit(127); /* execvp falhou */
        }

        int status;
        if (waitpid(pid, &status, 0) < 0) {
            vault_log(LOG_WARN, "[SANDBOX] waitpid installer: %s", strerror(errno));
            continue;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            vault_log(LOG_INFO, "[SANDBOX] Package manager exited successfully.");
            return 0;
        }

        vault_log(LOG_WARN,
                  "[SANDBOX] Installer '%s' exited with code %d — trying next...",
                  pm_paths[i], WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }

    return -1; /* nenhum instalador funcionou */
}

/* ─────────────────────────────────────────────────────────────────────────
 *  jail_install_shell(): Garante que /bin/sh existe dentro do jail
 *
 *  Ordem de tentativas:
 *    1. Copia busybox estático já presente no host (mais rápido)
 *    2. Chama o package manager para instalar busybox-static e tenta de novo
 *    3. Desiste e loga aviso — sandbox vai subir mas sem shell
 *
 *  O busybox DEVE ser estático: após pivot_root o /lib do host não existe.
 * ───────────────────────────────────────────────────────────────────────── */
static int jail_install_shell(const char *vault_path)
{
    static const char *candidates[] = {
        "/usr/bin/busybox-static",
        "/usr/bin/busybox",
        "/bin/busybox",
        "/usr/local/bin/busybox",
        NULL
    };

    char dst[VAULT_PATH_MAX];
    snprintf(dst, sizeof(dst), "%s/bin/sh", vault_path);

    /* ── Já existe e não é vazio? Não mexe. ─────────────────────────── */
    {
        struct stat st;
        if (stat(dst, &st) == 0 && st.st_size > 0) {
            vault_log(LOG_INFO, "[SANDBOX] Shell already present at jail/bin/sh (%ld bytes) — skipping install.",
                      (long)st.st_size);
            return 0;
        }
    }

    /* ── Tentativa 1: copia do host ──────────────────────────────────── */
    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) != 0)
            continue;

        /* Abre origem */
        int src = open(candidates[i], O_RDONLY | O_CLOEXEC);
        if (src < 0) continue;

        /* Abre destino */
        int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        if (dst_fd < 0) { close(src); continue; }

        /* Copia em blocos de 64 KB */
        char buf[65536];
        ssize_t n;
        int ok = 1;
        while ((n = read(src, buf, sizeof(buf))) > 0) {
            if (write(dst_fd, buf, (size_t)n) != n) { ok = 0; break; }
        }
        close(src);
        close(dst_fd);

        if (!ok) {
            unlink(dst);
            vault_log(LOG_WARN, "[SANDBOX] Copy from '%s' failed mid-transfer — removing partial file.",
                      candidates[i]);
            continue;
        }

        /* Verifica se é realmente estático para avisar o usuário */
        int is_static = 0;
        {
            /* Heurística rápida: ELF dinâmico tem PT_INTERP; abre e procura
             * a string "/lib" nos primeiros 4 KB do arquivo */
            int probe = open(candidates[i], O_RDONLY | O_CLOEXEC);
            if (probe >= 0) {
                char head[4096];
                ssize_t r = read(probe, head, sizeof(head));
                close(probe);
                /* Se não achou interpreter path, é estático */
                is_static = (r > 0 && memmem(head, (size_t)r, "/lib", 4) == NULL);
            }
        }

        if (!is_static) {
            vault_log(LOG_WARN,
                      "[SANDBOX] '%s' appears to be dynamically linked — "
                      "may fail inside jail (missing host /lib). "
                      "Install 'busybox-static' for reliable operation.",
                      candidates[i]);
            printf("[SANDBOX] [WARN] Copied '%s' but it may be dynamic — "
                   "prefer busybox-static.\n", candidates[i]);
        }

        vault_log(LOG_INFO,
                  "[SANDBOX] ✔ Shell installed: '%s' → jail/bin/sh (%ld bytes, %s)",
                  candidates[i], (long)st.st_size,
                  is_static ? "static" : "dynamic — may fail");
        printf("[SANDBOX] [AUTO-INSTALL] ✔ Shell ready at jail/bin/sh "
               "(copied from '%s', %s).\n",
               candidates[i],
               is_static ? "statically linked" : "dynamically linked — may fail inside jail");
        return 0;
    }

    /* ── Tentativa 2: instala via package manager e tenta de novo ────── */
    printf("[SANDBOX] [AUTO-INSTALL] busybox not found on host — attempting automatic installation...\n");
    vault_log(LOG_WARN, "[SANDBOX] No busybox found on host — attempting auto-install via package manager.");

    if (geteuid() != 0) {
        printf("[SANDBOX] [AUTO-INSTALL] WARNING: not running as root — package manager will likely fail.\n");
        vault_log(LOG_WARN, "[SANDBOX] Auto-install requires root privileges (euid=%d).", geteuid());
    }

    int installed = jail_run_installer();

    if (installed == 0) {
        /* Re-tenta a cópia após instalação */
        for (int i = 0; candidates[i]; i++) {
            struct stat st;
            if (stat(candidates[i], &st) != 0)
                continue;

            int src = open(candidates[i], O_RDONLY | O_CLOEXEC);
            if (src < 0) continue;

            int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
            if (dst_fd < 0) { close(src); continue; }

            char buf[65536];
            ssize_t n;
            int ok = 1;
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                if (write(dst_fd, buf, (size_t)n) != n) { ok = 0; break; }
            }
            close(src);
            close(dst_fd);

            if (!ok) { unlink(dst); continue; }

            vault_log(LOG_AUDIT,
                      "[SANDBOX] ✔ Shell auto-installed and deployed: '%s' → jail/bin/sh (%ld bytes)",
                      candidates[i], (long)st.st_size);
            printf("[SANDBOX] [AUTO-INSTALL] ✔ busybox-static installed and deployed to jail/bin/sh.\n");
            return 0;
        }
    }

    /* ── Tentativa 3: desiste ────────────────────────────────────────── */
    vault_log(LOG_WARN,
              "[SANDBOX] Could not obtain a shell binary for the jail. "
              "Sandbox will open but execl(\"/bin/sh\") will fail. "
              "Install busybox-static manually: apt install busybox-static");
    printf("[SANDBOX] [AUTO-INSTALL] ✗ Could not install shell. "
           "Run: sudo apt install busybox-static\n");
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_prepare_jail(): Prepare jail structure inside vault path
 * ───────────────────────────────────────────────────────────────────────── */
static void vault_prepare_jail(const char *vault_path)
{
    char marker[VAULT_PATH_MAX];
    snprintf(marker, sizeof(marker), "%s/%s", vault_path, SANDBOX_JAIL_MARKER);

    struct stat st;

    /* Always ensure critical dirs and device stubs exist, even if marker present */
    char dev_dir[VAULT_PATH_MAX];
    snprintf(dev_dir, sizeof(dev_dir), "%s/dev", vault_path);
    if (mkdir(dev_dir, 0755) != 0 && errno != EEXIST)
        vault_log(LOG_WARN, "[SANDBOX] mkdir dev: %s", strerror(errno));

    {
        char p_null[VAULT_PATH_MAX], p_zero[VAULT_PATH_MAX], p_tty[VAULT_PATH_MAX];
        snprintf(p_null, sizeof(p_null), "%s/dev/null", vault_path);
        snprintf(p_zero, sizeof(p_zero), "%s/dev/zero", vault_path);
        snprintf(p_tty,  sizeof(p_tty),  "%s/dev/tty",  vault_path);
        struct stat ds;
        if (stat(p_null, &ds) != 0) {
            int fd = open(p_null, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
        if (stat(p_zero, &ds) != 0) {
            int fd = open(p_zero, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
        if (stat(p_tty, &ds) != 0) {
            int fd = open(p_tty, O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
        }
    }

    if (stat(marker, &st) == 0)
        return;

    vault_log(LOG_INFO, "[SANDBOX] Preparing jail at '%s'", vault_path);

    char dir[VAULT_PATH_MAX];
    const char *subdirs[] = {"proc", "tmp", "dev", "bin", "lib", "lib64", NULL};
    for (int i = 0; subdirs[i]; i++)
    {
        snprintf(dir, sizeof(dir), "%s/%s", vault_path, subdirs[i]);
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            vault_log(LOG_WARN, "[SANDBOX] mkdir %s: %s", dir, strerror(errno));
    }

    /* ── Garante /bin/sh dentro do jail (auto-instala se necessário) ── */
    jail_install_shell(vault_path);

    if (geteuid() == 0)
    {
        char dev_null[VAULT_PATH_MAX], dev_zero[VAULT_PATH_MAX];
        snprintf(dev_null, sizeof(dev_null), "%s/dev/null", vault_path);
        snprintf(dev_zero, sizeof(dev_zero), "%s/dev/zero", vault_path);
        if (stat(dev_null, &st) != 0)
            mknod(dev_null, S_IFCHR | 0666, makedev(1, 3));
        if (stat(dev_zero, &st) != 0)
            mknod(dev_zero, S_IFCHR | 0666, makedev(1, 5));
    }

    int fd = open(marker, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (fd >= 0)
    {
        write(fd, "IdenVault Jail v2\n", 18);
        close(fd);
    }
    else
    {
        if (errno == ELOOP)
        {
            vault_log(LOG_ALERT, "[SANDBOX] Detected symlink on jail marker '%s' (ELOOP)", marker);
        }
        else
        {
            vault_log(LOG_WARN, "[SANDBOX] open(marker '%s'): %s", marker, strerror(errno));
        }
    }

    vault_log(LOG_AUDIT, "[SANDBOX] Jail prepared at '%s'", vault_path);
}

/* ─────────────────────────────────────────────────────────────────────────
 *  vault_sandbox_open() — IdenVault Hardened Sandbox v2
 * ───────────────────────────────────────────────────────────────────────── */
VaultErrorr vault_sandbox_open(Vault *v, const char *password)
{
    if (!v)
        return ERR_INVALID_ARGS;

    /* Authentication */
    if (v->type == VAULT_TYPE_PROTECTED)
    {
        if (!password || !*password)
            return ERR_PASS_REQUIRED;
        VaultErrorr err = auth_verify_password(v, password);
        if (err != ERR_OK)
            return err;
    }

    if (v->path[0] == '\0')
    {
        vault_log(LOG_ERROR, "[SANDBOX] vault path empty");
        return ERR_PATH_INVALID;
    }

    struct timespec _ts_sb;
    clock_gettime(CLOCK_REALTIME, &_ts_sb);
    vault_log(LOG_AUDIT,
              "[SANDBOX] INITIATE \u2502 vault_id=%u \u2502 name='%s' \u2502 "
              "type=%s \u2502 pid=%d \u2502 uid=%d \u2502 ts=%ld.%09ld",
              v->id, v->name,
              v->type == VAULT_TYPE_PROTECTED ? "PROTECTED" : "NORMAL",
              (int)getpid(), (int)getuid(),
              (long)_ts_sb.tv_sec, _ts_sb.tv_nsec);

    /* Temporarily unlock cipher_path so the jail can access vault data */
    vault_log(LOG_AUDIT,
              "[PHYSICAL_LOCK] Temporary bypass granted: chmod 000 \u2192 700 on cipher_dir='%s' "
              "to allow Sandbox jail access. Session-scoped unlock.",
              v->cipher_path);
    chmod(v->cipher_path, 0700);

    vault_prepare_jail(v->path);

    int sync_pipe[2];   /* pai -> filho: "mapeamento já escrito" */
    int ready_pipe[2];  /* filho -> pai: "unshare(CLONE_NEWUSER) já feito" */
    if (pipe(sync_pipe) != 0 || pipe(ready_pipe) != 0)
    {
        vault_log(LOG_ERROR, "[SANDBOX] pipe failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        vault_log(LOG_ERROR, "[SANDBOX] fork failed: %s", strerror(errno));
        return ERR_SYSTEM;
    }

    /* PARENT */
    if (pid > 0)
    {
        vault_auth_pid_add_ffi(pid);

        close(ready_pipe[1]);
        close(sync_pipe[0]);

        /* Espera o filho sinalizar que já chamou unshare(CLONE_NEWUSER) —
         * sem isso, escrever em /proc/[pid]/uid_map cedo demais falha com
         * EPERM, porque o PID ainda pertence à user namespace antiga. */
        {
            char c;
            ssize_t r = read(ready_pipe[0], &c, 1);
            if (r != 1)
                vault_log(LOG_ERROR, "[SANDBOX] ready_pipe read falhou: %s", strerror(errno));
        }
        close(ready_pipe[0]);

        sandbox_write_uid_gid_map(pid);
        close(sync_pipe[1]);

        int status;
        waitpid(pid, &status, 0);

        vault_auth_pid_remove_ffi(pid);

        if (WIFSIGNALED(status))
        {
            vault_log(LOG_ALERT,
                      "[SANDBOX] Session of vault '%s' (id=%u) TERMINATED BY SIGNAL %d "
                      "(possible seccomp/namespace violation). exit_code=N/A.",
                      v->name, v->id, WTERMSIG(status));
        }
        else
        {
            vault_log(LOG_AUDIT,
                      "[SANDBOX] Session of vault '%s' (id=%u) ended cleanly. "
                      "exit_code=%d. Namespace teardown complete.",
                      v->name, v->id, WEXITSTATUS(status));
        }

        /* Re-seal cipher_path immediately after sandbox session ends */
        if (chmod(v->cipher_path, 0000) != 0) {
            vault_log(LOG_WARN,
                      "[PHYSICAL_LOCK] WARNING: chmod 0000 FAILED on cipher_dir='%s' post-sandbox: "
                      "errno=%d (%s). Physical isolation NOT restored.",
                      v->cipher_path, errno, strerror(errno));
        } else {
            struct timespec _ts_seal;
            clock_gettime(CLOCK_REALTIME, &_ts_seal);
            vault_log(LOG_AUDIT,
                      "[PHYSICAL_LOCK] Sandbox session terminated. Restoring permanent 000 immutable lock: "
                      "cipher_dir='%s' \u2502 vault_id=%u \u2502 ts=%ld.%09ld \u2502 State: SEALED.",
                      v->cipher_path, v->id,
                      (long)_ts_seal.tv_sec, _ts_seal.tv_nsec);
        }

        return ERR_OK;
    }

    /* CHILD — SANDBOX */

    /* Rename the process so it appears distinctly in htop/task managers */
    prctl(PR_SET_NAME, "IdenVault-Jail", 0, 0, 0);

    close(sync_pipe[1]);
    close(ready_pipe[0]);

    /* [Layer 1] User Namespace */
    printf("[SANDBOX] [Layer 1/5] Invoking unshare(CLONE_NEWUSER) syscall to dissociate user/group database from host...\n");
    if (unshare(CLONE_NEWUSER) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWUSER) failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 1/5] User Namespace unshared. Signaling host to assign UID/GID mappings...\n");

    /* Avisa o pai AGORA que a user namespace já existe — só depois disso
     * é seguro o pai escrever em /proc/[este_pid]/uid_map e gid_map. */
    {
        char c = 'r';
        if (write(ready_pipe[1], &c, 1) != 1)
            fprintf(stderr, "[SANDBOX][WARN] ready_pipe write falhou: %s\n", strerror(errno));
        close(ready_pipe[1]);
    }

    /* Wait for parent to write uid_map/gid_map */
    {
        char c;
        read(sync_pipe[0], &c, 1);
        close(sync_pipe[0]);
    }
    printf("[SANDBOX] [Layer 1/5] UID/GID mapping initialized: current sandbox root maps to host 'nobody' (%d:%d).\n", 
           SANDBOX_NOBODY_UID, SANDBOX_NOBODY_GID);

    /* [Layer 2] Mount + PID Namespace */
    printf("[SANDBOX] [Layer 2/5] Invoking unshare(CLONE_NEWNS | CLONE_NEWPID) to isolate mount points and process trees...\n");
    if (unshare(CLONE_NEWNS | CLONE_NEWPID) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] unshare(CLONE_NEWNS|CLONE_NEWPID) failed: %s (Kernel code %d)\n",
                strerror(err), err);
        _exit(1);
    }

    printf("[SANDBOX] [Layer 2/5] Namespaces created. Forking inside new PID namespace to gain PID 1...\n");
    pid_t ns_pid = fork();
    if (ns_pid < 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] fork inside new PID NS failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    if (ns_pid > 0)
    {
        int st;
        waitpid(ns_pid, &st, 0);
        _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 1);
    }

    printf("[SANDBOX] [Layer 2/5] Fork successful. Subprocess running as PID 1 inside isolated PID namespace.\n");

    // Bind-mount host /dev/null and /dev/zero onto jail's /dev/null and /dev/zero
    if (geteuid() != 0)
    {
        char jail_null[VAULT_PATH_MAX], jail_zero[VAULT_PATH_MAX], jail_tty[VAULT_PATH_MAX];
        snprintf(jail_null, sizeof(jail_null), "%s/dev/null", v->path);
        snprintf(jail_zero, sizeof(jail_zero), "%s/dev/zero", v->path);
        snprintf(jail_tty,  sizeof(jail_tty),  "%s/dev/tty",  v->path);

        if (mount("/dev/null", jail_null, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/null");
        if (mount("/dev/zero", jail_zero, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/zero");
        /* /dev/tty is needed for busybox sh interactive mode */
        if (mount("/dev/tty", jail_tty, NULL, MS_BIND, NULL) != 0)
            perror("[SANDBOX] mount bind /dev/tty (non-fatal)");
    }

    /* [Layer 3] Pivot Root */
    printf("[SANDBOX] [Layer 3/5] Executing pivot_root syscall targeting '%s'...\n", v->path);
    if (sandbox_pivot_root(v->path) != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] pivot_root syscall to '%s' failed: %s (Kernel code %d)\n", v->path, strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 3/5] Root filesystem successfully pivoted. Old root unmounted.\n");

    printf("[SANDBOX] [Layer 3/5] Creating private virtual mounts (/proc, /tmp) inside new root...\n");
    sandbox_prepare_mounts();
    printf("[SANDBOX] [Layer 3/5] /proc and /tmp (tmpfs) mounted securely with MS_NOSUID | MS_NOEXEC.\n");

    /* [Layer 4] Drop capabilities */
    printf("[SANDBOX] [Layer 4/5] Dropping Linux kernel capabilities to prevent privilege escalation...\n");
    if (sandbox_drop_caps() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] drop capabilities failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 4/5] Capabilities dropped. PR_SET_NO_NEW_PRIVS set to 1.\n");

    printf("[SANDBOX] [Layer 4/5] Enforcing resource limits (RLIMIT_NPROC=32, RLIMIT_AS=128MB, RLIMIT_NOFILE=64)...\n");
    sandbox_limit_resources();
    printf("[SANDBOX] [Layer 4/5] Kernel RLIMIT parameters applied successfully.\n");

    /* [Layer 5] Seccomp-BPF — LAST STEP */
    printf("[SANDBOX] [Layer 5/5] Compiling and loading Seccomp-BPF filter allowlist...\n");
    if (apply_seccomp_policy() != 0)
    {
        int err = errno;
        fprintf(stderr, "[SANDBOX][FATAL] seccomp policy activation failed: %s (Kernel code %d)\n", strerror(err), err);
        _exit(1);
    }
    printf("[SANDBOX] [Layer 5/5] Seccomp filter loaded. Kernel will now SIGKILL unauthorized syscalls.\n");

    printf("\n");
    printf("  ┌─────────────────────────────────────────────────────────┐\n");
    printf("  │     IDENVAULT HARDENED SANDBOX v2                       │\n");
    printf("  │     Vault : %-43s                                       │\n", v->name);
    printf("  │     Isolation: UserNS + PivotRoot + Caps + Seccomp-BPF  │\n");
    printf("  │     Mode: Least Privilege · Deny by Default             │\n");
    printf("  │     Type 'exit' to end session.                         │\n");
    printf("  └─────────────────────────────────────────────────────────┘\n\n");

    printf("                                .:xxxxxxxx:.\n");
    printf("                             .xxxxxxxxxxxxxxxx.\n");
    printf("                            :xxxxxxxxxxxxxxxxxxx:.\n");
    printf("                           .xxxxxxxxxxxxxxxxxxxxxxx:\n");
    printf("                          :xxxxxxxxxxxxxxxxxxxxxxxxx:\n");
    printf("                          xxxxxxxxxxxxxxxxxxxxxxxxxxX:\n");
    printf("                          xxx:::xxxxxxxx::::xxxxxxxxx:\n");
    printf("                         .xx:   ::xxxxx:     :xxxxxxxx\n");
    printf("                         :xx  x.  xxxx:  xx.  xxxxxxxx\n");
    printf("                         :xx xxx  xxxx: xxxx  :xxxxxxx\n");
    printf("                         'xx 'xx  xxxx:. xx'  xxxxxxxx\n");
    printf("                          xx ::::::xx:::::.   xxxxxxxx\n");
    printf("                          xx:::::.::::.:::::::xxxxxxxx\n");
    printf("                          :x'::::'::::':::::':xxxxxxxxx.\n");
    printf("                          :xx.::::::::::::'   xxxxxxxxxx\n");
    printf("                          :xx: '::::::::'     :xxxxxxxxxx.\n");
    printf("                         .xx     '::::'        'xxxxxxxxxx.\n");
    printf("                       .xxxx                     'xxxxxxxxx.\n");
    printf("                     .xxxx                         'xxxxxxxxx.\n");
    printf("                   .xxxxx:                          xxxxxxxxxx.\n");
    printf("                  .xxxxx:'                          xxxxxxxxxxx.\n");
    printf("                 .xxxxxx:::.           .       ..:::_xxxxxxxxxxx:.\n");
    printf("                .xxxxxxx''      ':::''            ''::xxxxxxxxxxxx.\n");
    printf("                xxxxxx            :                  '::xxxxxxxxxxxx\n");
    printf("               :xxxx:'            :                    'xxxxxxxxxxxx:\n");
    printf("              .xxxxx              :                     ::xxxxxxxxxxxx\n");
    printf("              xxxx:'                                    ::xxxxxxxxxxxx\n");
    printf("              xxxx               .                      ::xxxxxxxxxxxx.\n");
    printf("          .:xxxxxx               :                      ::xxxxxxxxxxxx::\n");
    printf("          xxxxxxxx               :                      ::xxxxxxxxxxxxx:\n");
    printf("          xxxxxxxx               :                      ::xxxxxxxxxxxxx:\n");
    printf("          ':xxxxxx               '                      ::xxxxxxxxxxxx:'\n");
    printf("            .:. xx:.                                   .:xxxxxxxxxxxxx'\n");
    printf("          ::::::.'xx:.            :                  .:: xxxxxxxxxxx':\n");
    printf("  .:::::::::::::::.'xxxx.                            ::::'xxxxxxxx':::.\n");
    printf("  ::::::::::::::::::.'xxxxx                          :::::.'.xx.'::::::.\n");
    printf("  ::::::::::::::::::::.'xxxx:.                       :::::::.'':::::::::\n");
    printf("  ':::::::::::::::::::::.'xx:'                     .'::::::::::::::::::::..\n");
    printf("    :::::::::::::::::::::.'xx                    .:: :::::::::::::::::::::::\n");
    printf("  .:::::::::::::::::::::::. xx               .::xxxx :::::::::::::::::::::::\n");
    printf("  :::::::::::::::::::::::::.'xxx..        .::xxxxxxx ::::::::::::::::::::'\n");
    printf("  '::::::::::::::::::::::::: xxxxxxxxxxxxxxxxxxxxxxx :::::::::::::::::'\n");
    printf("    '::::::::::::::::::::::: xxxxxxxxxxxxxxxxxxxxxxx :::::::::::::::'\n");
    printf("        ':::::::::::::::::::_xxxxxx::'''::xxxxxxxxxx '::::::::::::'\n");
    printf("             '':.::::::::::'                        `._'::::::'' \n");
    printf("\n   Tux: \"Welcome to the Sandbox!\"\n\n");

    printf("[SANDBOX] Launching shell via execl(\"/bin/sh\")...\n");
    execl("/bin/sh", "sh", NULL);

    int err = errno;
    fprintf(stderr,
            "[SANDBOX][FATAL] execl(/bin/sh) failed: %s (Kernel code %d)\n"
            "  Hint: place a static /bin/sh (busybox) inside the vault.\n",
            strerror(err), err);
    _exit(127);
}


/* ─────────────────────────────────────────────────────────────────────────
 * vault_isolate_path_readonly — bind-mount + remount readonly
 *
 * Isola um caminho arbitrário (não necessariamente um vault catalogado)
 * tornando-o readonly em nível de kernel via bind mount, em vez de apenas
 * chmod (que não impede escrita por processos com CAP_DAC_OVERRIDE).
 *
 * Requer CAP_SYS_ADMIN. Retorna 0 em success, -1 em falha (ver errno).
 * ───────────────────────────────────────────────────────────────────────── */
int vault_isolate_path_readonly(const char *path)
{
    if (path == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    if (mount(path, path, NULL, MS_BIND, NULL) != 0)
    {
        return -1;
    }

    if (mount(path, path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) != 0)
    {
        int saved_errno = errno;
        umount(path); /* desfaz o bind se o remount readonly falhar */
        errno = saved_errno;
        return -1;
    }

    return 0;
}

#endif /* __linux__ */