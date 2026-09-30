/*
 * Demo "malicious" program: it starts clean, then re-execs *itself*
 * (well, /bin/true) with LD_PRELOAD injected into its own envp - the
 * classic "run clean first, then inject on a later exec" trick.
 * Used to show exec_guard catching an execve() the traced program makes
 * on its own, not just the one exec_guard itself launched it with.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

extern char **environ;

int main(void)
{
    printf("reexec_demo: running clean, pid=%d\n", getpid());

    char *envp[32];
    int n = 0;
    for (; environ[n] && n < 30; n++)
        envp[n] = environ[n];
    envp[n++] = "LD_PRELOAD=/tmp/does_not_exist_evil.so";
    envp[n] = NULL;

    char *argv[] = { "/bin/true", NULL };

    printf("reexec_demo: now self-exec'ing /bin/true with LD_PRELOAD injected...\n");
    execve("/bin/true", argv, envp);
    perror("reexec_demo: execve failed");
    return 1;
}
