"""Shared network binding helper. Defaults to loopback unless SENTINEL_BIND_PUBLIC=1."""

import logging
import os

log = logging.getLogger(__name__)


def bind_host() -> str:
    if os.environ.get("SENTINEL_BIND_PUBLIC") == "1":
        log.warning(
            "SENTINEL_BIND_PUBLIC=1 set - binding 0.0.0.0. "
            "Ensure upstream proxy is required."
        )
        return "0.0.0.0"
    return os.environ.get("SENTINEL_BIND_HOST", "127.0.0.1")
