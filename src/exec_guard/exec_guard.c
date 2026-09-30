/*
 * exec_guard: launches a target program under seccomp(SECCOMP_RET_TRACE) +
 * ptrace, and inspects the real argv/envp of every execve()/execveat() it
 * makes (including the very first one) before the syscall runs. If the
 * environment contains LD_PRELOAD, LD_LIBRARY_PATH or GLIBC_TUNABLES, the
 * syscall is denied with EPERM instead of being allowed to run.
 *
 * This exists because the eBPF LSM bprm_check_security hook can't read
 * argv/envp at all (bprm->mm isn't attached to any task yet at that point),
 * so it can only act blind (e.g. force secureexec). Trapping execve at the
 * seccomp/ptrace layer instead sees the syscall before the kernel has done
 * anything, while argv/envp are still ordinary pointers into the calling
 * process's own (already-current) address space.
 *
 * Scope: traces only the single launched process, not any children it
 * forks (no PTRACE_O_TRACEFORK/TRACECLONE). A forked child inherits the
 * seccomp filter but, with no tracer attached to it, any RET_TRACE syscall
 * it makes fails with ENOSYS instead of being inspected.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif

static const char *const deny_prefixes[] = {
    "LD_PRELOAD=",
    "LD_LIBRARY_PATH=",
    "GLIBC_TUNABLES=",
};
#define NUM_DENY (sizeof(deny_prefixes) / sizeof(deny_prefixes[0]))

static void install_seccomp_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(NO_NEW_PRIVS)");
        _exit(127);
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == -1) {
        perror("seccomp");
        _exit(127);
    }
}

static unsigned long read_remote_word(int memfd, unsigned long addr)
{
    unsigned long val = 0;
    pread(memfd, &val, sizeof(val), (off_t)addr);
    return val;
}

static char *read_remote_string(int memfd, unsigned long addr)
{
    size_t cap = 128, len = 0;
    char *buf = malloc(cap);
    if (!buf)
        return NULL;

    while (1) {
        char chunk[64];
        ssize_t n = pread(memfd, chunk, sizeof(chunk), (off_t)(addr + len));
        if (n <= 0) {
            free(buf);
            return NULL;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (len + 1 >= cap) {
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) {
                    free(buf);
                    return NULL;
                }
                buf = nb;
            }
            buf[len++] = chunk[i];
            if (chunk[i] == '\0')
                return buf;
        }
    }
}

static const char *matches_deny_list(const char *env_entry)
{
    for (size_t i = 0; i < NUM_DENY; i++) {
        size_t plen = strlen(deny_prefixes[i]);
        if (strncmp(env_entry, deny_prefixes[i], plen) == 0)
            return deny_prefixes[i];
    }
    return NULL;
}

/* Returns a malloc'd copy of the first denied env entry found, or NULL. */
static char *scan_envp(int memfd, unsigned long envp_addr)
{
    for (int i = 0; i < 4096; i++) {
        unsigned long ptr = read_remote_word(memfd, envp_addr + i * sizeof(unsigned long));
        if (ptr == 0)
            break;

        char *entry = read_remote_string(memfd, ptr);
        if (!entry)
            continue;

        if (matches_deny_list(entry))
            return entry;

        free(entry);
    }
    return NULL;
}

static void deny_current_syscall(pid_t pid)
{
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.orig_rax = SYS_getpid; /* harmless substitute so nothing dangerous runs */
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    int status;
    ptrace(PTRACE_SYSCALL, pid, NULL, 0); /* step to that syscall's exit */
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status))
        return;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rax = (unsigned long)-EPERM;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        install_seccomp_filter();
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0); /* child's self-SIGSTOP */

    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL);
    ptrace(PTRACE_CONT, pid, NULL, 0);

    char memfile[64];
    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", pid);

    while (1) {
        pid_t w = waitpid(pid, &status, 0);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (WIFEXITED(status)) {
            printf("exec_guard: target exited with status %d\n", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            printf("exec_guard: target killed by signal %d\n", WTERMSIG(status));
            return 128 + WTERMSIG(status);
        }

        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);
        int event = status >> 16;

        if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            unsigned long envp_addr;
            const char *syscall_name;
            if (regs.orig_rax == SYS_execve) {
                envp_addr = regs.rdx;
                syscall_name = "execve";
            } else {
                envp_addr = regs.r10;
                syscall_name = "execveat";
            }

            int memfd = open(memfile, O_RDONLY);
            char *hit = memfd >= 0 ? scan_envp(memfd, envp_addr) : NULL;
            if (memfd >= 0)
                close(memfd);

            if (hit) {
                printf("exec_guard: BLOCKED %s() - denied env var: %s\n", syscall_name, hit);
                free(hit);
                deny_current_syscall(pid);
            } else {
                printf("exec_guard: allowed %s()\n", syscall_name);
            }

            ptrace(PTRACE_CONT, pid, NULL, 0);
            continue;
        }

        /* Forward any other signal untouched; swallow our own SIGTRAP stops. */
        int deliver = (sig == SIGTRAP) ? 0 : sig;
        ptrace(PTRACE_CONT, pid, NULL, deliver);
    }

    return 0;
}
