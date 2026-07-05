"""The node-consumer must run exactly the way its container runs it.

The compose service runs ``python node_consumer.py`` from the image's
``WORKDIR /app/ai-engine`` — the detector half of the offline node path:
Redis stream in, scored ``node_alerts`` rows out.
"""

import os
import subprocess
import sys

import yaml

_AIDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_COMPOSE = os.path.abspath(os.path.join(_AIDIR, "..", "..", "docker-compose.yml"))


def test_consumer_imports_standalone_like_the_container():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-c", "import node_consumer"],
        cwd=_AIDIR,  # mirrors WORKDIR /app/ai-engine
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


def test_node_consumer_is_composed_as_the_rls_bypassing_owner():
    """node_alerts is owner-only for writes (20260627_001); sentinel_app got
    SELECT only (20260703_001). Wired as the RLS-enforced sentinel_app role
    the detector would fail every INSERT and no alert is ever stored — the
    node looks healthy while detecting nothing.
    """
    with open(_COMPOSE) as fh:
        compose = yaml.safe_load(fh)
    svc = compose["services"]["node-consumer"]
    assert svc["command"] == ["python", "node_consumer.py"]
    env = dict(e.split("=", 1) for e in svc["environment"])
    db_url = env["DATABASE_URL"]
    assert (
        "sentinel_app" not in db_url
    ), f"node-consumer must not connect as the RLS-enforced sentinel_app role: {db_url}"
    assert db_url.startswith("postgresql://sentinel:"), db_url
    assert env["REDIS_URL"].startswith("redis://")
    # alerts can only exist after the schema does
    assert svc["depends_on"]["db-migrate"]["condition"] == (
        "service_completed_successfully"
    )
    assert "ports" not in svc
    assert "privileged" not in svc
