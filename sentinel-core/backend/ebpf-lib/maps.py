"""High-level BPF map abstractions for SENTINEL.

Wraps raw BPF map file-descriptor operations behind typed, dict-like
classes.  When eBPF is unavailable the maps fall back to plain
in-memory Python dicts so that dependent code can run in containers,
CI, or development laptops without kernel support.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

from ebpf_lib import EBPF_AVAILABLE
from ebpf_lib.loader import MapReader

logger = logging.getLogger("sentinel.ebpf.maps")


class BPFHashMap:
    """Dict-like wrapper over a BPF_MAP_TYPE_HASH.

    Falls back to an in-memory ``dict`` when eBPF is not available or
    the map file descriptor is invalid.
    """

    def __init__(
        self,
        map_fd: int = -1,
        key_size: int = 4,
        value_size: int = 4,
    ) -> None:
        self._key_size = key_size
        self._value_size = value_size
        self._fallback: Dict[bytes, bytes] = {}
        self._lock = threading.Lock()
        self._use_kernel = EBPF_AVAILABLE and map_fd >= 0
        self._reader = MapReader(map_fd) if self._use_kernel else None

        if not self._use_kernel:
            logger.debug(
                "BPFHashMap using in-memory fallback (fd=%d, ebpf=%s)",
                map_fd,
                EBPF_AVAILABLE,
            )

    def _pad(self, data: bytes, size: int) -> bytes:
        if len(data) >= size:
            return data[:size]
        return data + b"\x00" * (size - len(data))

    def get(self, key: bytes) -> Optional[bytes]:
        key = self._pad(key, self._key_size)
        if self._use_kernel and self._reader:
            val = self._reader.lookup(key)
            if val is not None:
                return val[: self._value_size]
            return None
        with self._lock:
            return self._fallback.get(key)

    def set(self, key: bytes, value: bytes) -> bool:
        key = self._pad(key, self._key_size)
        value = self._pad(value, self._value_size)
        if self._use_kernel and self._reader:
            return self._reader.update(key, value)
        with self._lock:
            self._fallback[key] = value
        return True

    def delete(self, key: bytes) -> bool:
        key = self._pad(key, self._key_size)
        if self._use_kernel and self._reader:
            return self._reader.delete(key)
        with self._lock:
            return self._fallback.pop(key, None) is not None

    def items(self) -> List[Tuple[bytes, bytes]]:
        if self._use_kernel and self._reader:
            result = []
            for k in self._reader.keys():
                v = self._reader.lookup(k)
                if v is not None:
                    result.append((k[: self._key_size], v[: self._value_size]))
            return result
        with self._lock:
            return list(self._fallback.items())

    def __contains__(self, key: bytes) -> bool:
        return self.get(self._pad(key, self._key_size)) is not None

    def __len__(self) -> int:
        if self._use_kernel and self._reader:
            return len(self._reader.keys())
        with self._lock:
            return len(self._fallback)


class BPFArrayMap:
    """Dict-like wrapper over a BPF_MAP_TYPE_ARRAY.

    Array maps are indexed by integer keys (0 .. max_entries-1).
    Falls back to an in-memory list when eBPF is unavailable.
    """

    def __init__(
        self,
        map_fd: int = -1,
        max_entries: int = 256,
        value_size: int = 8,
    ) -> None:
        self._max_entries = max_entries
        self._value_size = value_size
        self._key_size = 4
        self._fallback: Dict[int, bytes] = {}
        self._lock = threading.Lock()
        self._use_kernel = EBPF_AVAILABLE and map_fd >= 0
        self._reader = MapReader(map_fd) if self._use_kernel else None

        if not self._use_kernel:
            logger.debug(
                "BPFArrayMap using in-memory fallback (fd=%d, entries=%d)",
                map_fd,
                max_entries,
            )

    def _key_to_bytes(self, index: int) -> bytes:
        return index.to_bytes(self._key_size, byteorder="little")

    def _pad_value(self, value: bytes) -> bytes:
        if len(value) >= self._value_size:
            return value[: self._value_size]
        return value + b"\x00" * (self._value_size - len(value))

    def get(self, index: int) -> Optional[bytes]:
        if not 0 <= index < self._max_entries:
            return None
        if self._use_kernel and self._reader:
            val = self._reader.lookup(self._key_to_bytes(index))
            if val is not None:
                return val[: self._value_size]
            return None
        with self._lock:
            return self._fallback.get(index)

    def set(self, index: int, value: bytes) -> bool:
        if not 0 <= index < self._max_entries:
            return False
        value = self._pad_value(value)
        if self._use_kernel and self._reader:
            return self._reader.update(self._key_to_bytes(index), value)
        with self._lock:
            self._fallback[index] = value
        return True

    def delete(self, index: int) -> bool:
        if not 0 <= index < self._max_entries:
            return False
        if self._use_kernel and self._reader:
            return self._reader.delete(self._key_to_bytes(index))
        with self._lock:
            return self._fallback.pop(index, None) is not None

    def items(self) -> List[Tuple[int, bytes]]:
        if self._use_kernel and self._reader:
            result = []
            for i in range(self._max_entries):
                v = self.get(i)
                if v is not None and v != b"\x00" * self._value_size:
                    result.append((i, v))
            return result
        with self._lock:
            return list(self._fallback.items())

    def __contains__(self, index: int) -> bool:
        return self.get(index) is not None

    def __len__(self) -> int:
        if self._use_kernel and self._reader:
            count = 0
            for i in range(self._max_entries):
                v = self.get(i)
                if v is not None and v != b"\x00" * self._value_size:
                    count += 1
            return count
        with self._lock:
            return len(self._fallback)
