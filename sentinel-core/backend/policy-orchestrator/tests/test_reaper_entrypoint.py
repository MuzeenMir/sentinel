"""The reaper must be importable exactly the way its container runs it.

The compose service runs ``python enforcement_reaper.py`` with the image's
``WORKDIR /app/policy-orchestrator`` while the shared modules (audit_logger,
_lib, vendors' deps) live one level up at ``/app`` — the same layout as this
repo. app.py bootstraps ``sys.path`` for that; the reaper must too, or the
container crash-loops with ModuleNotFoundError and expired enforcement
actions are never rolled back.
"""

import os
import subprocess
import sys

_PODIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_reaper_imports_standalone_like_the_container():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-c", "import enforcement_reaper"],
        cwd=_PODIR,  # mirrors WORKDIR /app/policy-orchestrator
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
