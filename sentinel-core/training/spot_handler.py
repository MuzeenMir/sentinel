"""
AWS EC2 Spot Instance Interruption Handler

Monitors the EC2 instance metadata service (IMDSv2) for Spot termination
notices.  When one is received the handler saves a checkpoint via the
caller-supplied callback and sets a flag so the training loop can exit
cleanly.

On non-AWS systems the metadata probe silently fails and monitoring
becomes a no-op — the process still benefits from SIGTERM/SIGINT
handling installed by ``install_signal_handlers()``.
"""
from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

_IMDS_TOKEN_URL = "http://169.254.169.254/latest/api/token"
_SPOT_ACTION_URL = "http://169.254.169.254/latest/meta-data/spot/instance-action"
_IMDS_TOKEN_TTL = 300
_IMDS_TIMEOUT = 2.0
_DEFAULT_POLL_INTERVAL = 5.0
_TOKEN_REFRESH_CYCLES = 30


class SpotInterruptionHandler:
    """
    Watches for AWS Spot interruption notices in a background thread.

    Parameters
    ----------
    save_fn:
        Callable invoked (exactly once) when an interruption is detected.
        Typically saves a training checkpoint.
    checkpoint_dir:
        Directory where checkpoint artefacts should be written.
        Passed through for caller convenience; not used internally.
    poll_interval:
        Seconds between metadata polls (default 5).
    """

    def __init__(
        self,
        save_fn: Optional[Callable[[], None]] = None,
        checkpoint_dir: Optional[str] = None,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ):
        self._save_fn = save_fn
        self.checkpoint_dir = checkpoint_dir
        self._poll_interval = poll_interval

        self._interrupted = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._is_aws: bool = False
        self._imds_token: Optional[str] = None

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def interrupted(self) -> bool:
        return self._interrupted

    @property
    def is_interrupted(self) -> bool:
        return self._interrupted

    def start(self):
        """Begin background monitoring (or no-op on non-AWS)."""
        self._is_aws = self._probe_imds()
        if self._is_aws:
            logger.info("AWS environment detected — monitoring Spot interruption notices")
            self._thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="spot-interruption-monitor",
            )
            self._thread.start()
        else:
            logger.info(
                "Non-AWS environment — Spot monitoring disabled "
                "(SIGTERM/SIGINT handlers still active)"
            )

    def start_monitoring(self):
        """Alias for :meth:`start`."""
        self.start()

    def stop(self):
        """Signal the monitoring thread to exit and wait for it."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=self._poll_interval + 2)
        logger.info("Spot interruption monitor stopped")

    # ── IMDS helpers ──────────────────────────────────────────────────────

    def _probe_imds(self) -> bool:
        try:
            resp = requests.put(
                _IMDS_TOKEN_URL,
                headers={"X-aws-ec2-metadata-token-ttl-seconds": str(_IMDS_TOKEN_TTL)},
                timeout=_IMDS_TIMEOUT,
            )
            if resp.status_code == 200:
                self._imds_token = resp.text
                return True
        except (requests.ConnectionError, requests.Timeout):
            pass
        return False

    def _refresh_token(self):
        try:
            resp = requests.put(
                _IMDS_TOKEN_URL,
                headers={"X-aws-ec2-metadata-token-ttl-seconds": str(_IMDS_TOKEN_TTL)},
                timeout=_IMDS_TIMEOUT,
            )
            if resp.status_code == 200:
                self._imds_token = resp.text
        except (requests.ConnectionError, requests.Timeout):
            logger.debug("IMDS token refresh failed — will retry next cycle")

    def _check_spot_action(self) -> Optional[dict]:
        headers = {}
        if self._imds_token:
            headers["X-aws-ec2-metadata-token"] = self._imds_token
        try:
            resp = requests.get(
                _SPOT_ACTION_URL, headers=headers, timeout=_IMDS_TIMEOUT,
            )
            if resp.status_code == 200:
                return resp.json()
        except (requests.ConnectionError, requests.Timeout):
            pass
        except ValueError:
            logger.warning("Non-JSON response from Spot metadata endpoint")
        return None

    # ── Monitor loop ──────────────────────────────────────────────────────

    def _monitor_loop(self):
        cycles_since_refresh = 0
        while not self._stop_event.is_set():
            cycles_since_refresh += 1
            if cycles_since_refresh >= _TOKEN_REFRESH_CYCLES:
                self._refresh_token()
                cycles_since_refresh = 0

            action = self._check_spot_action()
            if action is not None:
                logger.warning(
                    "Spot interruption notice: action=%s time=%s",
                    action.get("action"), action.get("time"),
                )
                self._on_interruption()
                return

            self._stop_event.wait(timeout=self._poll_interval)

    def _on_interruption(self):
        self._interrupted = True
        if self._save_fn is not None:
            try:
                logger.info("Saving checkpoint before Spot termination…")
                self._save_fn()
                logger.info("Checkpoint saved successfully")
            except Exception:
                logger.exception("Failed to save checkpoint during Spot interruption")


def install_signal_handlers(
    save_fn: Optional[Callable[[], None]] = None,
) -> SpotInterruptionHandler:
    """
    Install process-level SIGTERM / SIGINT handlers that save a checkpoint
    and exit.

    Returns a lightweight :class:`SpotInterruptionHandler` whose
    ``interrupted`` property reflects whether a signal was caught (mainly
    useful for testing; the handler calls ``sys.exit`` so the property is
    only observable in the brief window before exit).
    """
    handler = SpotInterruptionHandler(save_fn=save_fn)

    def _on_signal(signum: int, _frame):
        name = signal.Signals(signum).name
        logger.warning("Received %s — saving checkpoint and exiting", name)
        handler._interrupted = True
        if save_fn is not None:
            try:
                save_fn()
                logger.info("Checkpoint saved after %s", name)
            except Exception:
                logger.exception("Failed to save checkpoint after %s", name)
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    logger.info("Signal handlers installed for SIGTERM and SIGINT")
    return handler
