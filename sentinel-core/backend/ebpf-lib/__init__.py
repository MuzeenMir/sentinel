"""SENTINEL eBPF library — kernel-level security instrumentation.

Provides abstractions over eBPF programs for XDP packet processing,
host intrusion detection, and runtime policy enforcement.

On systems without eBPF support (containers, IoT, older kernels),
all components degrade gracefully to no-op or user-space fallbacks.
"""

EBPF_AVAILABLE = False

try:
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    # SYS_bpf = 321 on x86_64
    EBPF_AVAILABLE = hasattr(libc, "syscall")
except Exception:
    pass
