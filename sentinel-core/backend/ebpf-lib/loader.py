"""eBPF program loader and ring-buffer reader for SENTINEL.

Manages the full lifecycle of compiled eBPF programs:
  1. Locate and verify ``.o`` ELF objects in ``ebpf-lib/compiled/``.
  2. Load programs into the kernel via ``bpf(BPF_PROG_LOAD, …)``.
  3. Attach to XDP interfaces, tracepoints, kprobes, or LSM hooks.
  4. Consume ring-buffer / perf-event output.
  5. Detach and unload on shutdown.

When the kernel does not support eBPF (containers, older kernels, or
missing CAP_BPF), every component degrades to a safe no-op stub so
that dependent services can still start and serve their HTTP APIs.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ebpf_lib import EBPF_AVAILABLE

logger = logging.getLogger("sentinel.ebpf.loader")

_COMPILED_DIR = os.environ.get(
    "EBPF_COMPILED_DIR",
    os.path.join(os.path.dirname(__file__), "..", "ebpf-lib", "compiled"),
)

_SIGNATURE_DIR = os.environ.get(
    "EBPF_SIGNATURE_DIR",
    os.path.join(os.path.dirname(__file__), "..", "ebpf-lib", "signatures"),
)


@dataclass(slots=True)
class ProgramInfo:
    """Metadata for a loaded eBPF program."""

    name: str
    prog_type: str
    attach_target: str
    fd: int
    sha256: str
    map_fds: Dict[str, int] = field(default_factory=dict)


class ProgramLoader:
    """Load, attach, and manage eBPF programs.

    In degraded mode (no kernel eBPF support or missing compiled
    objects) all operations succeed silently with ``fd = -1`` so that
    callers can distinguish real attachment from dry-run.
    """

    def __init__(
        self,
        compiled_dir: Optional[str] = None,
        audit_callback: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._compiled_dir = Path(compiled_dir or _COMPILED_DIR)
        self._audit_cb = audit_callback
        self._loaded: Dict[str, ProgramInfo] = {}
        self._lock = threading.Lock()

        if not EBPF_AVAILABLE:
            logger.warning(
                "eBPF syscall not available; ProgramLoader running in stub mode"
            )

    def _audit(self, action: str, name: str, detail: str = "") -> None:
        record = {
            "ts": time.time(),
            "action": action,
            "program": name,
            "detail": detail,
        }
        logger.info("audit: %s %s %s", action, name, detail)
        if self._audit_cb:
            self._audit_cb(record)

    def _resolve_object(self, name: str) -> Path:
        """Resolve a program name like ``xdp/xdp_flow`` to the compiled ELF."""
        candidates = [
            self._compiled_dir / f"{name}.o",
            self._compiled_dir / f"{name.replace('/', '_')}.o",
            self._compiled_dir / name / f"{name.rsplit('/', 1)[-1]}.o",
        ]
        for path in candidates:
            if path.is_file():
                return path
        raise FileNotFoundError(
            f"Compiled eBPF object not found for '{name}'; "
            f"searched {[str(c) for c in candidates]}"
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _verify_signature(self, obj_path: Path, digest: str) -> None:
        sig_path = Path(_SIGNATURE_DIR) / f"{obj_path.stem}.sig"
        if not sig_path.is_file():
            logger.debug(
                "No signature file for %s (signature enforcement disabled)",
                obj_path.name,
            )
            return
        expected = sig_path.read_text().strip().split()[0]
        if expected != digest:
            raise PermissionError(
                f"eBPF object {obj_path.name} signature mismatch: "
                f"expected {expected[:16]}…, got {digest[:16]}…"
            )

    def load(
        self,
        name: str,
        prog_type: str = "xdp",
        attach_target: str = "",
    ) -> ProgramInfo:
        """Load and optionally attach an eBPF program.

        Returns a ``ProgramInfo`` with ``fd >= 0`` when the program was
        loaded into the kernel, or ``fd = -1`` in dry-run / stub mode.

        Raises ``FileNotFoundError`` if the compiled ``.o`` file is missing.
        Raises ``PermissionError`` if signature verification fails.
        """
        obj_path = self._resolve_object(name)
        digest = self._sha256(obj_path)
        self._verify_signature(obj_path, digest)

        fd = -1
        map_fds: Dict[str, int] = {}

        if EBPF_AVAILABLE:
            fd, map_fds = self._kernel_load(obj_path, prog_type, attach_target)

        info = ProgramInfo(
            name=name,
            prog_type=prog_type,
            attach_target=attach_target,
            fd=fd,
            sha256=digest,
            map_fds=map_fds,
        )

        with self._lock:
            self._loaded[name] = info

        self._audit(
            "load",
            name,
            f"type={prog_type} target={attach_target} fd={fd} sha256={digest[:16]}",
        )
        return info

    def _kernel_load(
        self,
        obj_path: Path,
        prog_type: str,
        attach_target: str,
    ) -> tuple[int, Dict[str, int]]:
        """Attempt real kernel load via libbpf / bcc bindings.

        Falls back to dry-run if the native loader is unavailable.
        """
        try:
            from bcc import BPF  # type: ignore[import-untyped]

            bpf = BPF(src_file=str(obj_path))
            fn = bpf.load_func(
                obj_path.stem, BPF.XDP if prog_type == "xdp" else BPF.KPROBE
            )
            if prog_type == "xdp" and attach_target:
                bpf.attach_xdp(attach_target, fn)
            fd = fn.fd if hasattr(fn, "fd") else -1
            return fd, {}
        except ImportError:
            logger.info(
                "bcc not installed; eBPF program %s loaded in dry-run mode",
                obj_path.name,
            )
        except Exception as exc:
            logger.warning("Kernel load failed for %s: %s", obj_path.name, exc)

        return -1, {}

    def unload(self, name: str) -> None:
        """Detach and unload a previously loaded program."""
        with self._lock:
            info = self._loaded.pop(name, None)
        if info is None:
            logger.warning("Program '%s' not loaded; nothing to unload", name)
            return
        if info.fd >= 0:
            try:
                os.close(info.fd)
            except OSError:
                pass
        self._audit("unload", name)

    def is_loaded(self, name: str) -> bool:
        with self._lock:
            return name in self._loaded

    def get_loaded(self) -> Dict[str, ProgramInfo]:
        with self._lock:
            return dict(self._loaded)


class RingBufferReader:
    """Consume events from one or more eBPF ring-buffer maps.

    In degraded mode the reader starts but never delivers events,
    allowing services to initialise without errors.
    """

    def __init__(self, poll_timeout_ms: int = 100) -> None:
        self._poll_timeout_ms = poll_timeout_ms
        self._registrations: Dict[str, _Registration] = {}
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        map_fd: int,
        callback: Callable[[Any], None],
    ) -> None:
        """Register a ring-buffer map for consumption."""
        with self._lock:
            self._registrations[name] = _Registration(
                name=name,
                map_fd=map_fd,
                callback=callback,
            )
        logger.info("Registered ring buffer '%s' (fd=%d)", name, map_fd)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop,
            name="ebpf-ringbuf-reader",
            daemon=True,
        )
        self._thread.start()
        logger.info("Ring buffer reader started")

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Ring buffer reader stopped")

    def poll(self, timeout_ms: Optional[int] = None) -> int:
        """Poll all registered ring buffers once.

        Returns the number of events consumed.
        """
        timeout = timeout_ms if timeout_ms is not None else self._poll_timeout_ms
        total = 0
        with self._lock:
            regs = list(self._registrations.values())
        for reg in regs:
            total += self._poll_one(reg, timeout)
        return total

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self.poll()
            except Exception as exc:
                logger.error("Ring buffer poll error: %s", exc)
            time.sleep(self._poll_timeout_ms / 1000.0)

    def _poll_one(self, reg: _Registration, timeout_ms: int) -> int:
        """Poll a single ring-buffer fd.

        Uses the native ring_buffer__poll when available, otherwise
        returns 0 (degraded mode).
        """
        if reg.map_fd < 0:
            return 0

        try:
            return self._native_poll(reg, timeout_ms)
        except Exception as exc:
            logger.debug("Native poll unavailable for '%s': %s", reg.name, exc)
            return 0

    @staticmethod
    def _native_poll(reg: _Registration, timeout_ms: int) -> int:
        """Attempt poll via bcc / libbpf bindings."""
        try:
            from bcc import BPF  # type: ignore[import-untyped]

            return BPF.ring_buffer_poll(reg.map_fd, timeout_ms) or 0
        except (ImportError, AttributeError):
            return 0


@dataclass(slots=True)
class _Registration:
    name: str
    map_fd: int
    callback: Callable[[Any], None]


class MapReader:
    """Read and write eBPF maps by file descriptor.

    Provides a dict-like interface over BPF hash / array maps.
    In degraded mode, operations are no-ops that return ``None``.
    """

    def __init__(self, map_fd: int) -> None:
        self._fd = map_fd

    def lookup(self, key: bytes) -> Optional[bytes]:
        if self._fd < 0 or not EBPF_AVAILABLE:
            return None
        return self._bpf_map_lookup(key)

    def update(self, key: bytes, value: bytes) -> bool:
        if self._fd < 0 or not EBPF_AVAILABLE:
            return False
        return self._bpf_map_update(key, value)

    def delete(self, key: bytes) -> bool:
        if self._fd < 0 or not EBPF_AVAILABLE:
            return False
        return self._bpf_map_delete(key)

    def keys(self) -> List[bytes]:
        if self._fd < 0 or not EBPF_AVAILABLE:
            return []
        return self._bpf_map_keys()

    def _bpf_map_lookup(self, key: bytes) -> Optional[bytes]:
        try:
            import ctypes

            key_buf = ctypes.create_string_buffer(key)
            val_buf = ctypes.create_string_buffer(256)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.syscall(
                321, 1, self._fd, ctypes.byref(key_buf), ctypes.byref(val_buf), 0
            )
            if ret == 0:
                return val_buf.raw
        except Exception as exc:
            logger.debug("bpf_map_lookup failed: %s", exc)
        return None

    def _bpf_map_update(self, key: bytes, value: bytes) -> bool:
        try:
            import ctypes

            key_buf = ctypes.create_string_buffer(key)
            val_buf = ctypes.create_string_buffer(value)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.syscall(
                321, 2, self._fd, ctypes.byref(key_buf), ctypes.byref(val_buf), 0
            )
            return ret == 0
        except Exception as exc:
            logger.debug("bpf_map_update failed: %s", exc)
        return False

    def _bpf_map_delete(self, key: bytes) -> bool:
        try:
            import ctypes

            key_buf = ctypes.create_string_buffer(key)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.syscall(321, 3, self._fd, ctypes.byref(key_buf), 0, 0)
            return ret == 0
        except Exception as exc:
            logger.debug("bpf_map_delete failed: %s", exc)
        return False

    def _bpf_map_keys(self) -> List[bytes]:
        result: List[bytes] = []
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            key_buf = ctypes.create_string_buffer(256)
            next_buf = ctypes.create_string_buffer(256)
            ret = libc.syscall(321, 4, self._fd, 0, ctypes.byref(next_buf), 0)
            while ret == 0:
                result.append(bytes(next_buf.raw))
                ctypes.memmove(key_buf, next_buf, 256)
                ret = libc.syscall(
                    321, 4, self._fd, ctypes.byref(key_buf), ctypes.byref(next_buf), 0
                )
        except Exception as exc:
            logger.debug("bpf_map_get_next_key failed: %s", exc)
        return result
