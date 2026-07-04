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

import yaml

_PODIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_COMPOSE = os.path.abspath(os.path.join(_PODIR, "..", "..", "docker-compose.yml"))


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


def test_reaper_compose_role_can_bypass_rls():
    """claim_expired_actions() is a deliberate cross-tenant scan (the reaper
    must revert EVERY tenant's expired actions) and never sets app.tenant_id,
    so the reaper must connect as the RLS-bypassing table owner. Wired to the
    RLS-enforced ``sentinel_app`` role it sees zero rows and silently reverts
    nothing — expired firewall rules would stay applied forever.
    """
    with open(_COMPOSE) as fh:
        compose = yaml.safe_load(fh)
    env_list = compose["services"]["enforcement-reaper"]["environment"]
    db_url = next(e.split("=", 1)[1] for e in env_list if e.startswith("DATABASE_URL="))
    assert "sentinel_app" not in db_url, (
        "enforcement-reaper must not connect as the RLS-enforced sentinel_app "
        f"role: {db_url}"
    )
    assert db_url.startswith("postgresql://sentinel:"), db_url
