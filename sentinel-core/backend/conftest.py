"""Root-level pytest configuration and debug instrumentation for SENTINEL backend."""

import importlib.util
import os
import sys
import json as _agent_json
from datetime import datetime as _agent_dt
import time as _agent_time
from pathlib import Path


def _agent_log_backend_root(hypothesis_id, message, data):
    """Write a single NDJSON debug log line for backend-wide pytest state."""
    try:
        payload = {
            "sessionId": "ba9959",
            "id": f"log_{int(_agent_time.time() * 1000)}",
            "timestamp": int(_agent_dt.utcnow().timestamp() * 1000),
            "location": "backend/conftest.py:session_start",
            "message": message,
            "data": data,
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
        }
        with open("/home/mir/sentinel/.cursor/debug-ba9959.log", "a") as _f:
            _f.write(_agent_json.dumps(payload) + "\n")
    except Exception:
        # Never let debug logging break tests
        pass


# region agent log
_backend_root = Path(__file__).resolve().parent
_agent_log_backend_root(
    "H2",
    "backend_pytest_session_start",
    {
        "cwd": os.getcwd(),
        "backend_root": str(_backend_root),
        "has_tests_pkg": (_backend_root / "tests" / "__init__.py").exists(),
        "sys_path_sample": sys.path[:5],
    },
)
# endregion

sys.path.insert(0, str(_backend_root))


def _alias_hyphen_package(disk_name: str, module_name: str) -> None:
    """Expose a hyphenated directory as an importable underscore package."""
    disk_dir = _backend_root / disk_name
    link_dir = _backend_root / module_name
    if link_dir.exists() or not disk_dir.is_dir():
        return
    try:
        link_dir.symlink_to(disk_name)
        return
    except OSError:
        pass
    init_file = disk_dir / "__init__.py"
    _spec = importlib.util.spec_from_file_location(
        module_name,
        init_file if init_file.exists() else None,
        submodule_search_locations=[str(disk_dir)],
    )
    if _spec and _spec.loader:
        _module = importlib.util.module_from_spec(_spec)
        _module.__path__ = [str(disk_dir)]
        sys.modules[module_name] = _module
        _spec.loader.exec_module(_module)


_alias_hyphen_package("ebpf-lib", "ebpf_lib")
_alias_hyphen_package("firewall-adapters", "firewall_adapters")


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_circuit_breakers():
    """Reset process-wide circuit breaker state between tests to avoid pollution."""
    try:
        from resilience import _breakers
        for br in _breakers.values():
            br._state = br.CLOSED
            br._failure_count = 0
            br._success_count = 0
            br._last_failure_time = 0.0
    except Exception:
        pass
    yield

