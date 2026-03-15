"""Ring buffer reader for consuming eBPF events in user-space.

Provides a high-level interface to poll BPF ring buffers and dispatch
decoded events to callbacks. Falls back to a simulated mode when BPF
runtime is unavailable (for development/testing).
"""

from __future__ import annotations

import ctypes
import logging
import os
import threading
import time
from typing import Any, Callable, Optional

from ..schemas.events import EVENT_STRUCT_MAP, PYTHON_EVENT_MAP, decode_event

logger = logging.getLogger("sentinel.ebpf.ringbuf")


class RingBufferReader:
    """Polls one or more BPF ring buffers and dispatches decoded events.

    Usage:
        reader = RingBufferReader()
        reader.register("flow_events", map_fd, on_flow_event)
        reader.start()   # background thread
        ...
        reader.stop()
    """

    def __init__(self, poll_timeout_ms: int = 100):
        self._poll_timeout_ms = poll_timeout_ms
        self._callbacks: dict[str, Callable[[Any], None]] = {}
        self._map_fds: dict[str, int] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._bpf_available = os.path.exists("/sys/fs/bpf") and os.getuid() == 0

    def register(self, name: str, map_fd: int,
                 callback: Callable[[Any], None]) -> None:
        """Register a ring buffer map for polling.

        Args:
            name: Human-readable name for this ring buffer.
            map_fd: File descriptor of the BPF_MAP_TYPE_RINGBUF map.
            callback: Called with each decoded Python event dataclass.
        """
        self._map_fds[name] = map_fd
        self._callbacks[name] = callback
        logger.info("Registered ring buffer '%s' (fd=%d)", name, map_fd)

    def start(self) -> None:
        """Start polling in a background daemon thread."""
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
        """Stop the polling thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Ring buffer reader stopped")

    def _poll_loop(self) -> None:
        """Main poll loop. Uses ring_buffer__poll when available."""
        if not self._bpf_available:
            logger.info(
                "BPF not available; ring buffer reader in standby mode"
            )
            while self._running:
                time.sleep(1)
            return

        rb = self._create_ring_buffer()
        if rb is None:
            logger.error("Failed to create ring buffer manager")
            return

        while self._running:
            try:
                self._poll_once(rb)
            except Exception:
                logger.exception("Error polling ring buffer")
                time.sleep(0.5)

    def _create_ring_buffer(self) -> Optional[Any]:
        """Create the libbpf ring_buffer manager via ctypes.

        Returns an opaque handle or None on failure.
        This is a placeholder for the full libbpf integration.
        """
        try:
            libbpf = ctypes.CDLL("libbpf.so.1")
        except OSError:
            try:
                libbpf = ctypes.CDLL("libbpf.so")
            except OSError:
                logger.warning("libbpf shared library not found")
                return None

        RING_BUFFER_CB = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_void_p,  # ctx
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # data_sz
        )

        ring_buffer_new = libbpf.ring_buffer__new
        ring_buffer_new.restype = ctypes.c_void_p
        ring_buffer_new.argtypes = [
            ctypes.c_int,     # map_fd
            RING_BUFFER_CB,   # sample_cb
            ctypes.c_void_p,  # ctx
            ctypes.c_void_p,  # opts
        ]

        self._libbpf = libbpf
        self._rb_cb_type = RING_BUFFER_CB
        self._rb_poll = libbpf.ring_buffer__poll
        self._rb_poll.restype = ctypes.c_int
        self._rb_poll.argtypes = [ctypes.c_void_p, ctypes.c_int]

        first_name = next(iter(self._map_fds))
        first_fd = self._map_fds[first_name]

        @RING_BUFFER_CB
        def _on_event(ctx, data, data_sz):
            try:
                raw = ctypes.string_at(data, data_sz)
                event = decode_event(raw)
                if event:
                    for cb in self._callbacks.values():
                        cb(event)
            except Exception:
                logger.exception("Error decoding ring buffer event")
            return 0

        self._cb_ref = _on_event

        rb = ring_buffer_new(first_fd, _on_event, None, None)
        if not rb:
            logger.error("ring_buffer__new returned NULL")
            return None

        ring_buffer_add = libbpf.ring_buffer__add
        ring_buffer_add.restype = ctypes.c_int
        ring_buffer_add.argtypes = [
            ctypes.c_void_p, ctypes.c_int,
            RING_BUFFER_CB, ctypes.c_void_p,
        ]
        for name, fd in list(self._map_fds.items())[1:]:
            ring_buffer_add(rb, fd, _on_event, None)

        return rb

    def _poll_once(self, rb: Any) -> None:
        """Single poll iteration."""
        ret = self._rb_poll(rb, self._poll_timeout_ms)
        if ret < 0:
            logger.debug("ring_buffer__poll returned %d", ret)
