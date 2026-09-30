#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsm_exec.skel.h"

struct allow_key {
    __u64 dev;
    __u64 ino;
};

static int add_tmpfs_allowlist_entry(int map_fd, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Warning: cannot stat '%s', skipping allowlist entry\n", path);
        return -1;
    }

    struct allow_key key = {
        .dev = (__u64)st.st_dev,
        .ino = (__u64)st.st_ino,
    };
    __u8 value = 1;

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Warning: failed to allowlist '%s'\n", path);
        return -1;
    }

    printf("Allowlisted tmpfs path: %s (dev=%llu ino=%llu)\n",
           path, (unsigned long long)key.dev, (unsigned long long)key.ino);
    return 0;
}

int main(int argc, char *argv[])
{
    struct lsm_exec *skel = lsm_exec__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load skeleton\n");
        return 1;
    }

    int map_fd = bpf_map__fd(skel->maps.tmpfs_allowlist);
    for (int i = 1; i < argc; i++)
        add_tmpfs_allowlist_entry(map_fd, argv[i]);

    struct bpf_link *link = bpf_program__attach(skel->progs.exec_audit);
    if (!link) {
        fprintf(stderr, "Failed to attach\n");
        lsm_exec__destroy(skel);
        return 1;
    }

    printf("LSM hook active. Press Ctrl-C to detach.\n");
    pause();

    bpf_link__destroy(link);
    lsm_exec__destroy(skel);
    return 0;
}