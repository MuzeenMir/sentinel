"""The node-collector must run exactly the way its container runs it.

The compose service runs ``python node_collector.py`` from the image's
``WORKDIR /app/data-collector``, tailing the bind-mounted host auditd log
onto the Redis stream — the first hop of the offline node detection path.

Also pins tail()'s rotation behavior: auditd rotates audit.log frequently
(max_log_file is 8MB by default), and a tailer holding the rotated-away fd
reads nothing forever — the node would silently go blind. tail() must return
on rotation so the supervisor loop in main() reopens the new file.
"""

import os
import subprocess
import sys
import threading
import time

import fakeredis
import yaml

_DCDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_COMPOSE = os.path.abspath(os.path.join(_DCDIR, "..", "..", "docker-compose.yml"))


def test_collector_imports_standalone_like_the_container():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-c", "import node_collector"],
        cwd=_DCDIR,  # mirrors WORKDIR /app/data-collector
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


def test_tail_returns_when_the_audit_log_rotates(tmp_path):
    from node_collector import NodeCollector

    path = tmp_path / "audit.log"
    path.write_text("")
    collector = NodeCollector(fakeredis.FakeStrictRedis(decode_responses=True))
    thread = threading.Thread(
        target=collector.tail, args=(str(path),), kwargs={"poll": 0.05}, daemon=True
    )
    thread.start()
    time.sleep(0.3)
    assert thread.is_alive()  # steady-state: tailing an unrotated file

    # auditd-style rotation: current log renamed away, fresh file created.
    path.rename(tmp_path / "audit.log.1")
    path.write_text("")
    thread.join(timeout=5)
    assert not thread.is_alive(), "tail() must return when the file rotates"


def test_node_collector_is_composed_to_tail_the_host_audit_log():
    with open(_COMPOSE) as fh:
        compose = yaml.safe_load(fh)
    svc = compose["services"]["node-collector"]
    assert svc["command"] == ["python", "node_collector.py"]
    env = dict(e.split("=", 1) for e in svc["environment"])
    assert env["REDIS_URL"].startswith("redis://")
    assert env["AUDIT_LOG_PATH"] == "/host/audit/audit.log"
    # host auditd log arrives read-only; the collector must never write it
    assert any(v.endswith(":/host/audit:ro") for v in svc["volumes"])
    assert "ports" not in svc
    assert "privileged" not in svc
