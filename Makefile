CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= gcc

BUILD    := build
SRC_BPF  := src/bpf
SRC_LOADER := src/loader
SRC_GUARD  := src/exec_guard
TESTS      := tests

# On stock Ubuntu 22.04, libbpf-dev is 0.5.0 and fails to parse this
# kernel's BTF ("failed to find valid kernel BTF"). If that happens, build
# libbpf from source with the system toolchain (see README) and point
# LIBBPF_DIR at its src/ directory, e.g.:
#   make LIBBPF_DIR=/path/to/libbpf-1.5.0/src
LIBBPF_DIR ?=
ifeq ($(LIBBPF_DIR),)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf 2>/dev/null) -lelf -lz
else
LIBBPF_CFLAGS := -I$(LIBBPF_DIR)
LIBBPF_LIBS   := $(LIBBPF_DIR)/libbpf.a -lelf -lz
endif

.PHONY: all clean

all: $(BUILD)/loader $(BUILD)/exec_guard $(BUILD)/reexec_demo

$(BUILD):
	mkdir -p $(BUILD)

# Regenerated from the running kernel's BTF every time - it's
# machine/kernel-specific and never checked in.
$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Named lsm_exec.o (not lsm_exec.bpf.o): bpftool gen skeleton derives the
# skeleton's struct/function prefix from the object's filename and only
# strips a trailing ".o", so ".bpf.o" would produce "lsm_exec_bpf" instead
# of the "lsm_exec" name loader.c expects.
$(BUILD)/lsm_exec.o: $(SRC_BPF)/lsm_exec.bpf.c $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/bpf -I$(BUILD) \
		-c $< -o $@

$(BUILD)/lsm_exec.skel.h: $(BUILD)/lsm_exec.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/loader: $(SRC_LOADER)/loader.c $(BUILD)/lsm_exec.skel.h
	$(CC) -Wall -O2 -g $(LIBBPF_CFLAGS) -I$(BUILD) $< $(LIBBPF_LIBS) -o $@

$(BUILD)/exec_guard: $(SRC_GUARD)/exec_guard.c | $(BUILD)
	$(CC) -Wall -O2 -g $< -o $@

$(BUILD)/reexec_demo: $(TESTS)/reexec_demo.c | $(BUILD)
	$(CC) -Wall -O2 -g $< -o $@

clean:
	rm -rf $(BUILD)
