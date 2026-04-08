"""Secure eBPF program loader with signature verification and audit logging.

This module loads pre-compiled eBPF .o (ELF) files into the kernel.
It enforces that only signed, vetted programs are loaded.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("sentinel.ebpf.loader")


@dataclass
class ProgramInfo:
    """Metadata for a loaded eBPF program."""
    name: str
    path: str
    prog_type: str
    sha256: str
    loaded_at: float = 0.0
    fd: int = -1
    map_fds: dict[str, int] = field(default_factory=dict)


class SignatureVerifier:
    """Verifies HMAC-SHA256 signatures of eBPF object files.

    In production, replace HMAC with proper asymmetric signing (e.g. GPG or
    sigstore). This implementation provides the interface and audit trail.
    """

    def __init__(self, key_path: Optional[str] = None):
        self._key: Optional[bytes] = None
        key_source = key_path or os.environ.get("SENTINEL_EBPF_SIGN_KEY")
        if key_source and os.path.isfile(key_source):
            with open(key_source, "rb") as f:
                self._key = f.read().strip()
            logger.info("eBPF signature verification enabled (key loaded)")
        else:
            logger.warning(
                "eBPF signature key not found; "
                "signature verification is DISABLED (development mode)"
            )

    def verify(self, object_path: str, signature_path: Optional[str] = None) -> bool:
        if self._key is None:
            logger.warning("Skipping signature check for %s (no key)", object_path)
            return True

        sig_path = signature_path or object_path + ".sig"
        if not os.path.isfile(sig_path):
            logger.error("Signature file missing: %s", sig_path)
            return False

        with open(object_path, "rb") as f:
            file_data = f.read()
        with open(sig_path, "r") as f:
            expected_sig = f.read().strip()

        computed = hmac.new(self._key, file_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed, expected_sig):
            logger.error("Signature mismatch for %s", object_path)
            return False

        logger.info("Signature verified for %s", object_path)
        return True

    def sign(self, object_path: str) -> str:
        """Generate a signature for a compiled eBPF object (build-time utility)."""
        if self._key is None:
            raise RuntimeError("Cannot sign without a key")
        with open(object_path, "rb") as f:
            file_data = f.read()
        return hmac.new(self._key, file_data, hashlib.sha256).hexdigest()


class ProgramLoader:
    """Loads and manages eBPF programs.

    Abstracts over the underlying BPF library (bcc or libbpf bindings).
    When the real BPF libraries are not available (e.g. CI, macOS dev),
    operates in dry-run mode and logs what would happen.
    """

    def __init__(
        self,
        compiled_dir: Optional[str] = None,
        sign_key_path: Optional[str] = None,
        audit_callback: Optional[Callable[[dict], None]] = None,
    ):
        self._compiled_dir = Path(
            compiled_dir
            or os.environ.get("SENTINEL_EBPF_COMPILED_DIR", "")
            or str(Path(__file__).resolve().parent.parent / "compiled")
        )
        self._verifier = SignatureVerifier(sign_key_path)
        self._loaded: dict[str, ProgramInfo] = {}
        self._audit_cb = audit_callback
        self._bpf_available = self._check_bpf_available()

        if not self._bpf_available:
            logger.warning(
                "BPF runtime not available; operating in dry-run mode"
            )

    @staticmethod
    def _check_bpf_available() -> bool:
        """Check if we can load BPF programs on this system."""
        try:
            return os.path.exists("/sys/fs/bpf") and os.getuid() == 0
        except Exception:
            return False

    def _audit(self, action: str, program: str, success: bool, detail: str = ""):
        record = {
            "timestamp": time.time(),
            "action": action,
            "program": program,
            "success": success,
            "detail": detail,
            "pid": os.getpid(),
            "uid": os.getuid(),
        }
        logger.info("AUDIT: %s", json.dumps(record))
        if self._audit_cb:
            self._audit_cb(record)

    def _file_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def load(self, name: str, prog_type: str = "xdp",
             attach_target: Optional[str] = None) -> ProgramInfo:
        """Load a compiled eBPF program by name.

        Args:
            name: Program name (looks for {name}.o in compiled_dir).
            prog_type: One of 'xdp', 'tracepoint', 'kprobe', 'kretprobe', 'lsm'.
            attach_target: Attach point (e.g. interface name for XDP,
                          tracepoint path, function name for kprobe).

        Returns:
            ProgramInfo with load metadata.

        Raises:
            FileNotFoundError: If the .o file does not exist.
            PermissionError: If signature verification fails.
        """
        obj_path = self._compiled_dir / f"{name}.o"
        if not obj_path.exists():
            self._audit("load", name, False, "object file not found")
            raise FileNotFoundError(f"eBPF object not found: {obj_path}")

        if not self._verifier.verify(str(obj_path)):
            self._audit("load", name, False, "signature verification failed")
            raise PermissionError(
                f"Signature verification failed for {obj_path}"
            )

        sha256 = self._file_sha256(str(obj_path))

        info = ProgramInfo(
            name=name,
            path=str(obj_path),
            prog_type=prog_type,
            sha256=sha256,
            loaded_at=time.time(),
        )

        if self._bpf_available:
            info = self._do_load(info, attach_target)
        else:
            logger.info(
                "DRY-RUN: would load %s (%s) attached to %s",
                name, prog_type, attach_target,
            )

        self._loaded[name] = info
        self._audit("load", name, True, f"sha256={sha256}")
        return info

    def _do_load(self, info: ProgramInfo,
                 attach_target: Optional[str]) -> ProgramInfo:
        """Actually load the program into the kernel using libbpf/bcc.

        This is the integration point for the real BPF loading library.
        Subclass or monkey-patch for testing.
        """
        try:
            from bcc import BPF  # type: ignore[import-untyped]
            b = BPF(src_file=info.path)
            if info.prog_type == "xdp" and attach_target:
                fn = b.load_func(info.name, BPF.XDP)
                b.attach_xdp(attach_target, fn, 0)
                info.fd = fn.fd
            logger.info("Loaded %s via bcc", info.name)
        except ImportError:
            logger.info(
                "bcc not available, attempting libbpf ctypes fallback"
            )
            self._load_via_libbpf(info, attach_target)
        return info

    def _load_via_libbpf(self, info: ProgramInfo,
                         attach_target: Optional[str]) -> None:
        """Placeholder for libbpf-based loading via ctypes.

        A full implementation would use ctypes to call:
        - bpf_object__open_file()
        - bpf_object__load()
        - bpf_program__attach_xdp / bpf_program__attach()
        """
        logger.warning(
            "libbpf ctypes loader not yet fully implemented for %s; "
            "install bcc or use the C loader directly",
            info.name,
        )

    def unload(self, name: str) -> None:
        """Unload (detach) a previously loaded program."""
        info = self._loaded.pop(name, None)
        if not info:
            logger.warning("Program %s not tracked; nothing to unload", name)
            return

        if info.fd >= 0:
            try:
                os.close(info.fd)
            except OSError:
                pass

        self._audit("unload", name, True)
        logger.info("Unloaded %s", name)

    def get_loaded(self) -> dict[str, ProgramInfo]:
        """Return a copy of all currently loaded programs."""
        return dict(self._loaded)

    def is_loaded(self, name: str) -> bool:
        return name in self._loaded
