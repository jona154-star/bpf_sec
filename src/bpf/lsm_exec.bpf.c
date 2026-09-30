#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define TMPFS_MAGIC 0x01021994

struct allow_key {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct allow_key);
    __type(value, __u8);
} tmpfs_allowlist SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_audit, struct linux_binprm *bprm)
{
    /*
     * bprm_check_security runs before bprm->mm is swapped into current,
     * so envp content (LD_PRELOAD, LD_LIBRARY_PATH, GLIBC_TUNABLES) can't
     * be read here. Force secureexec instead: glibc's dynamic linker
     * ignores those variables itself once AT_SECURE is set, same as for
     * setuid binaries.
     */
    bpf_bprm_opts_set(bprm, BPF_F_BPRM_SECUREEXEC);

    struct inode *inode = BPF_CORE_READ(bprm->file, f_inode);

    /*
     * i_nlink == 0 means this inode was never linked into a directory
     * (memfd/anonymous-inode exec) or lost its last link while still
     * open (exec of a deleted file) - the two classic fileless-exec
     * patterns collapse into the same signal.
     */
    if (BPF_CORE_READ(inode, i_nlink) == 0)
        return -EPERM;

    /*
     * Any exec from a tmpfs-backed mount (/tmp, /dev/shm, /run, ...) is
     * denied unless its (dev, ino) is explicitly whitelisted.
     */
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (BPF_CORE_READ(sb, s_magic) == TMPFS_MAGIC) {
        struct allow_key key = {
            .dev = BPF_CORE_READ(sb, s_dev),
            .ino = BPF_CORE_READ(inode, i_ino),
        };
        if (!bpf_map_lookup_elem(&tmpfs_allowlist, &key))
            return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";