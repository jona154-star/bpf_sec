#!/bin/bash
# Demonstrates exec_guard.c against a few scenarios.
set -u
cd "$(dirname "$0")/../build"

pass=0
fail=0

check() {
    local desc="$1" expect="$2" actual="$3"
    if [ "$expect" = "$actual" ]; then
        echo "  PASS: $desc (got $actual)"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc (expected $expect, got $actual)"
        fail=$((fail + 1))
    fi
}

echo "=== Scenario 1: clean launch, no denied env vars ==="
echo "  \$ ./exec_guard /bin/true"
./exec_guard /bin/true
check "exec allowed" "0" "$?"
echo

echo "=== Scenario 2: LD_PRELOAD set on the launch itself ==="
echo "  \$ LD_PRELOAD=/tmp/does_not_exist_evil.so ./exec_guard /bin/true"
LD_PRELOAD=/tmp/does_not_exist_evil.so ./exec_guard /bin/true 2>/dev/null
check "exec blocked (child exits 127 after EPERM)" "127" "$?"
echo

echo "=== Scenario 3: LD_LIBRARY_PATH set on the launch itself ==="
echo "  \$ LD_LIBRARY_PATH=/tmp/fake_libs ./exec_guard /bin/true"
LD_LIBRARY_PATH=/tmp/fake_libs ./exec_guard /bin/true
check "exec blocked" "127" "$?"
echo

echo "=== Scenario 4: GLIBC_TUNABLES set on the launch itself ==="
echo "  \$ GLIBC_TUNABLES=glibc.malloc.check=1 ./exec_guard /bin/true"
GLIBC_TUNABLES=glibc.malloc.check=1 ./exec_guard /bin/true
check "exec blocked" "127" "$?"
echo

echo "=== Scenario 5: program starts clean, then re-execs ITSELF with LD_PRELOAD injected ==="
echo "  \$ ./exec_guard ./reexec_demo   (no malicious env at launch)"
./exec_guard ./reexec_demo
check "second execve() (self re-exec) blocked" "1" "$?"
echo

echo "=== Baseline for comparison: scenario 5's program run WITHOUT exec_guard ==="
echo "  \$ ./reexec_demo   (nothing intercepts its self re-exec)"
./reexec_demo
echo "  (exit code: $?, unguarded - the re-exec with injected LD_PRELOAD was allowed to run)"
echo

echo "=== Results: $pass passed, $fail failed ==="
