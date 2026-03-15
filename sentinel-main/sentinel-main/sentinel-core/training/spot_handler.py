"""
Spot Instance interruption handler for SENTINEL training.

Polls the EC2 instance metadata endpoint for Spot termination notices
and triggers checkpoint saves when a 2-minute warning is received.
"""
import os
import signal
import threading
import logging
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

METADATA_BASE = "http://169.254.169.254"
TOKEN_URL = f"{METADATA_BASE}/latest/api/token"
SPOT_ACTION_URL = f"{METADATA_BASE}/latest/meta-data/spot/instance-action"
TOKEN_TTL_SECONDS = 21600


class SpotInterruptionHandler:
    """
    Monitors EC2 Spot Instance termination notices and fires a callback
    so the training loop can save a checkpoint before the instance dies.

    Usage:
        handler = SpotInterruptionHandler(save_fn=my_checkpoint_fn)
        handler.start()
        ...  # training loop
        handler.stop()
    """

    def __init__(
        self,
        save_fn: Callable[[], None],
        poll_interval: float = 5.0,
        checkpoint_dir: Optional[str] = None,
    ):
        self._save_fn = save_fn
        self._poll_interval = poll_interval
        self._checkpoint_dir = checkpoint_dir or os.getcwd()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._interrupted = False
        self._imds_token: Optional[str] = None

    @property
    def interrupted(self) -> bool:
        return self._interrupted

    def start(self) -> None:
        if self._thread is not None:
            return
        logger.info("Spot interruption handler started (poll every %.1fs)", self._poll_interval)
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval + 2)
            self._thread = None

    def _get_imds_token(self) -> Optional[str]:
        """Obtain an IMDSv2 session token."""
        try:
            req = urllib.request.Request(
                TOKEN_URL,
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": str(TOKEN_TTL_SECONDS)},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.read().decode()
        except Exception:
            return None

    def _check_spot_action(self) -> Optional[dict]:
        """Query the Spot interruption metadata endpoint."""
        if self._imds_token is None:
            self._imds_token = self._get_imds_token()
        if self._imds_token is None:
            return None

        try:
            req = urllib.request.Request(
                SPOT_ACTION_URL,
                headers={"X-aws-ec2-metadata-token": self._imds_token},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None  # no interruption scheduled
            self._imds_token = None
            return None
        except Exception:
            self._imds_token = None
            return None

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            action = self._check_spot_action()
            if action is not None:
                logger.warning(
                    "SPOT INTERRUPTION NOTICE: action=%s time=%s",
                    action.get("action"),
                    action.get("time"),
                )
                self._interrupted = True
                self._handle_interruption(action)
                return
            self._stop_event.wait(self._poll_interval)

    def _handle_interruption(self, action: dict) -> None:
        """Save checkpoint and write interruption metadata."""
        logger.warning("Saving emergency checkpoint...")
        try:
            self._save_fn()
        except Exception:
            logger.exception("Failed to save checkpoint on Spot interruption")

        meta_path = os.path.join(self._checkpoint_dir, "spot_interruption.json")
        try:
            with open(meta_path, "w") as f:
                json.dump(
                    {
                        "action": action.get("action"),
                        "time": action.get("time"),
                        "detected_at": datetime.utcnow().isoformat(),
                    },
                    f,
                    indent=2,
                )
        except Exception:
            logger.exception("Failed to write interruption metadata")


def install_signal_handlers(save_fn: Callable[[], None]) -> None:
    """
    Install SIGTERM / SIGINT handlers that trigger a checkpoint save.
    Useful as a fallback on non-Spot instances or when running in Docker.
    """

    def _handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.warning("Received %s -- saving checkpoint before exit", sig_name)
        try:
            save_fn()
        except Exception:
            logger.exception("Checkpoint save failed on signal %s", sig_name)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)
