# bpf_sec

Two independent exec-time security controls, built to cover different parts
of the same decision tree (detect/deny risky `execve()`s), because no single
kernel hook can see everything with blocking power:

- **`lsm_exec`** - an eBPF LSM program attached to `bprm_check_security`.
  Runs in-kernel, can deny the exec outright, but cannot read `argv`/`envp`
  content (the new program's memory isn't attached to any task yet at this
  point in `fs/exec.c`). It does what it *can* see from kernel structures:
  - forces `secureexec` (`AT_SECURE`) on every exec, so glibc itself ignores
    `LD_PRELOAD` / `LD_LIBRARY_PATH` / `GLIBC_TUNABLES` for the new program
  - blocks exec of any inode with `i_nlink == 0` (memfd/anonymous-inode exec,
    and exec of an already-unlinked/deleted file - same signal, either way)
  - blocks exec from any tmpfs-backed mount (`/tmp`, `/dev/shm`, `/run`, ...)
    unless the file's `(dev, ino)` is explicitly allowlisted

- **`exec_guard`** - a userspace seccomp(`SECCOMP_RET_TRACE`) + `ptrace`
  supervisor. Traps `execve`/`execveat` *before* the kernel touches them,
  while `argv`/`envp` are still ordinary pointers in the caller's own,
  already-current address space - so it can do exactly what the LSM hook
  can't: read the real environment and deny based on its content.

## Layout

```
src/bpf/lsm_exec.bpf.c       eBPF LSM program (bprm_check_security)
src/loader/loader.c          libbpf loader/attacher + tmpfs allowlist CLI
src/exec_guard/exec_guard.c  seccomp+ptrace exec supervisor (standalone)
tests/reexec_demo.c          demo program: execs clean, then self-execs
                              with LD_PRELOAD injected on the second call
tests/test_exec_guard.sh     exec_guard scenario tests
```

## Prerequisites

- `clang`, `bpftool`, kernel headers with `CONFIG_BPF_LSM=y`
- `bpf` present in `/sys/kernel/security/lsm` (kernel cmdline needs
  `lsm=...,bpf`)
- `libbpf` new enough to parse this kernel's BTF. **Known issue on Ubuntu
  22.04**: the packaged `libbpf-dev` is 0.5.0 (2022) and fails with
  `libbpf: failed to find valid kernel BTF` against newer kernels, even
  though `/sys/kernel/btf/vmlinux` is fine. No newer package exists in
  Ubuntu 22.04's repos. Workaround: build libbpf from source with the
  *system* toolchain (a prebuilt libbpf from elsewhere, e.g. a buildroot
  output tree, will likely be linked against a different glibc and fail at
  link time with `undefined reference to __isoc23_*`):

  ```sh
  git clone --branch v1.5.0 https://github.com/libbpf/libbpf.git
  cd libbpf/src
  make CC=gcc AR=ar BUILD_STATIC_ONLY=1
  ```

  Then build this repo with `make LIBBPF_DIR=/path/to/libbpf/src`.

## Build

```sh
make                              # uses pkg-config libbpf by default
make LIBBPF_DIR=/path/to/libbpf/src   # if system libbpf can't load BTF
```

Outputs land in `build/` (gitignored - `vmlinux.h` is regenerated from the
running kernel's BTF every build, so it's machine-specific).

## Run

```sh
sudo ./build/loader                    # lsm_exec, no tmpfs exceptions
sudo ./build/loader /tmp/some_tool     # allowlist a tmpfs path by (dev, ino)
# Ctrl-C to detach

./build/exec_guard /bin/true           # exec_guard needs no root
```

## Test

```sh
make
./tests/test_exec_guard.sh
```
