"""SENTINEL eBPF program loader.

Provides secure loading, lifecycle management, and ring buffer consumption
for all SENTINEL eBPF programs. Uses libbpf via ctypes or bcc as backend.
"""

from .program_loader import ProgramLoader, ProgramInfo
from .ring_buffer import RingBufferReader

__all__ = ["ProgramLoader", "ProgramInfo", "RingBufferReader"]
