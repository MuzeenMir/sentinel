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

# Allow "import ebpf_lib" even though the directory on disk is "ebpf-lib".
_ebpf_lib_dir = _backend_root / "ebpf-lib"
_ebpf_lib_link = _backend_root / "ebpf_lib"
if not _ebpf_lib_link.exists() and _ebpf_lib_dir.is_dir():
    try:
        _ebpf_lib_link.symlink_to("ebpf-lib")
    except OSError:
        _spec = importlib.util.spec_from_file_location(
            "ebpf_lib",
            _ebpf_lib_dir / "__init__.py",
            submodule_search_locations=[str(_ebpf_lib_dir)],
        )
        if _spec and _spec.loader:
            _module = importlib.util.module_from_spec(_spec)
            _module.__path__ = [str(_ebpf_lib_dir)]
            sys.modules["ebpf_lib"] = _module
            _spec.loader.exec_module(_module)

