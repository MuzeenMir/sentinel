# SENTINEL eBPF programs build system
# Requires: clang >= 12, llvm, linux-headers, libbpf-dev
#
# Usage:
#   make all          - compile all eBPF programs
#   make vmlinux      - generate vmlinux.h from BTF
#   make sign         - sign all compiled objects
#   make clean        - remove compiled objects
#
# The compiled .o files are placed in compiled/ and are what
# the Python loader expects at runtime.

CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
STRIP      ?= llvm-strip

ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX_H  := programs/common/vmlinux.h

CFLAGS     := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I programs/common \
              -Wall -Werror

OUTDIR     := compiled

# Source files
XDP_SRCS        := $(wildcard programs/xdp/*.c)
TRACEPOINT_SRCS := $(wildcard programs/tracepoint/*.c)
LSM_SRCS        := $(wildcard programs/lsm/*.c)

ALL_SRCS := $(XDP_SRCS) $(TRACEPOINT_SRCS) $(LSM_SRCS)
ALL_OBJS := $(patsubst programs/%.c,$(OUTDIR)/%.o,$(ALL_SRCS))

.PHONY: all clean vmlinux sign

all: $(OUTDIR) $(ALL_OBJS)

$(OUTDIR):
	mkdir -p $(OUTDIR)/xdp $(OUTDIR)/tracepoint $(OUTDIR)/lsm

# Generate vmlinux.h from the running kernel's BTF data
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile eBPF C to object files
$(OUTDIR)/%.o: programs/%.c $(VMLINUX_H)
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(STRIP) -g $@

sign:
	@echo "Signing compiled eBPF objects..."
	@for obj in $(ALL_OBJS); do \
		if [ -f "$$obj" ]; then \
			python3 -c "from loader.program_loader import SignatureVerifier; \
				v = SignatureVerifier(); \
				sig = v.sign('$$obj'); \
				open('$$obj.sig', 'w').write(sig)" && \
			echo "  Signed: $$obj"; \
		fi; \
	done

clean:
	rm -rf $(OUTDIR)
