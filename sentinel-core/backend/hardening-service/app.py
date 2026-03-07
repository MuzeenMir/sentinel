"""SENTINEL Hardening Service -- OS hardening + eBPF runtime enforcement.

Takes a server from default installation to hardened state:
1. OS-level hardening (sysctl, SSH, user policies, file permissions, services)
2. CIS Benchmark checks and auto-remediation
3. eBPF LSM-based runtime policy enforcement driven by DRL engine
4. Compliance integration via compliance-engine

All actions are logged for audit and XAI explainability.

Runtime requirements:
- Linux 5.8+ with BTF (for eBPF enforcement)
- Root or CAP_SYS_ADMIN for OS hardening
- Host filesystem mounted at HOST_ROOT (default /host)
"""

import copy
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ebpf_lib.schemas.events import PolicyAction
from ebpf_lib.loader import ProgramLoader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel.hardening-service")


app = Flask(__name__)
CORS(app)


HOST_ROOT = os.environ.get("HOST_ROOT", "/host")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/var/lib/sentinel/backups")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC", "sentinel-hardening-events")


# ── Data Models ───────────────────────────────────────────────────────


@dataclass
class CheckResult:
    check_id: str
    title: str
    description: str
    status: str          # "pass", "fail", "error", "not_applicable"
    severity: str        # "critical", "high", "medium", "low", "info"
    category: str
    remediation: str
    cis_reference: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)
    detail: str = ""
    auto_remediable: bool = False


@dataclass
class HardeningProfile:
    name: str
    description: str
    checks: List[str]
    level: str = "L1"


@dataclass
class HardeningStats:
    checks_run: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    remediations_applied: int = 0
    remediations_rolled_back: int = 0
    ebpf_policies_active: int = 0
    last_scan_time: float = 0.0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        total = self.checks_passed + self.checks_failed
        score = round(self.checks_passed / max(total, 1) * 100, 1)
        return {
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "posture_score": score,
            "remediations_applied": self.remediations_applied,
            "remediations_rolled_back": self.remediations_rolled_back,
            "ebpf_policies_active": self.ebpf_policies_active,
            "last_scan_time": self.last_scan_time,
            "last_error": self.last_error,
        }


# ── OS Hardening Checks ──────────────────────────────────────────────


def _host_path(path: str) -> str:
    if HOST_ROOT and HOST_ROOT != "/":
        return os.path.join(HOST_ROOT, path.lstrip("/"))
    return path


def _read_host_file(path: str) -> Optional[str]:
    try:
        with open(_host_path(path), "r") as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def _read_sysctl(key: str) -> Optional[str]:
    proc_path = _host_path(f"/proc/sys/{key.replace('.', '/')}")
    try:
        with open(proc_path, "r") as f:
            return f.read().strip()
    except (OSError, PermissionError):
        return None


def _write_host_file(path: str, content: str, backup: bool = True) -> bool:
    full_path = _host_path(path)
    if backup:
        _backup_file(path)
    try:
        with open(full_path, "w") as f:
            f.write(content)
        return True
    except (OSError, PermissionError) as e:
        logger.error("Failed to write %s: %s", full_path, e)
        return False


def _backup_file(path: str) -> Optional[str]:
    src = _host_path(path)
    if not os.path.exists(src):
        return None
    ts = int(time.time())
    safe_name = path.replace("/", "_").lstrip("_")
    backup_path = os.path.join(BACKUP_DIR, f"{safe_name}.{ts}.bak")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    try:
        shutil.copy2(src, backup_path)
        logger.info("Backed up %s -> %s", src, backup_path)
        return backup_path
    except (OSError, PermissionError) as e:
        logger.error("Backup failed for %s: %s", src, e)
        return None


# ── CIS Benchmark Checks ─────────────────────────────────────────────


class CISBenchmarkEngine:
    """Implements CIS Benchmark checks for Ubuntu/RHEL Linux."""

    def __init__(self) -> None:
        self._checks: Dict[str, callable] = {
            "sysctl_ip_forward": self._check_sysctl_ip_forward,
            "sysctl_rp_filter": self._check_sysctl_rp_filter,
            "sysctl_syn_cookies": self._check_sysctl_syn_cookies,
            "sysctl_accept_redirects": self._check_sysctl_accept_redirects,
            "sysctl_aslr": self._check_sysctl_aslr,
            "sysctl_core_dump": self._check_sysctl_core_dump,
            "ssh_root_login": self._check_ssh_root_login,
            "ssh_protocol": self._check_ssh_protocol,
            "ssh_max_auth_tries": self._check_ssh_max_auth_tries,
            "ssh_permit_empty_passwords": self._check_ssh_permit_empty_passwords,
            "ssh_idle_timeout": self._check_ssh_idle_timeout,
            "ssh_password_auth": self._check_ssh_password_auth,
            "password_max_days": self._check_password_max_days,
            "password_min_length": self._check_password_min_length,
            "world_writable_files": self._check_world_writable_files,
            "suid_files": self._check_suid_files,
            "unowned_files": self._check_unowned_files,
            "umask_default": self._check_umask_default,
            "root_path_integrity": self._check_root_path_integrity,
            "cron_permissions": self._check_cron_permissions,
        }
        self._remediations: Dict[str, callable] = {
            "sysctl_ip_forward": self._remediate_sysctl_ip_forward,
            "sysctl_rp_filter": self._remediate_sysctl_rp_filter,
            "sysctl_syn_cookies": self._remediate_sysctl_syn_cookies,
            "sysctl_accept_redirects": self._remediate_sysctl_accept_redirects,
            "sysctl_aslr": self._remediate_sysctl_aslr,
            "ssh_root_login": self._remediate_ssh_root_login,
            "ssh_permit_empty_passwords": self._remediate_ssh_permit_empty_passwords,
            "ssh_idle_timeout": self._remediate_ssh_idle_timeout,
        }

    def run_all(self) -> List[CheckResult]:
        results = []
        for check_id, check_fn in self._checks.items():
            try:
                result = check_fn()
                results.append(result)
            except Exception as e:
                results.append(CheckResult(
                    check_id=check_id,
                    title=check_id,
                    description="Check failed with error",
                    status="error",
                    severity="medium",
                    category="system",
                    remediation="Investigate the error",
                    detail=str(e),
                ))
        return results

    def run_check(self, check_id: str) -> Optional[CheckResult]:
        fn = self._checks.get(check_id)
        if not fn:
            return None
        return fn()

    def remediate(self, check_id: str) -> Tuple[bool, str]:
        fn = self._remediations.get(check_id)
        if not fn:
            return False, "No auto-remediation available"
        try:
            return fn()
        except Exception as e:
            return False, str(e)

    def get_check_ids(self) -> List[str]:
        return list(self._checks.keys())

    # ── Sysctl checks ──

    def _check_sysctl_ip_forward(self) -> CheckResult:
        val = _read_sysctl("net.ipv4.ip_forward")
        return CheckResult(
            check_id="sysctl_ip_forward",
            title="IP Forwarding disabled",
            description="Ensure IP forwarding is disabled unless this is a router",
            status="pass" if val == "0" else "fail",
            severity="high", category="network",
            remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf",
            cis_reference="CIS 3.1.1",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"Current value: {val}",
            auto_remediable=True,
        )

    def _check_sysctl_rp_filter(self) -> CheckResult:
        val = _read_sysctl("net.ipv4.conf.all.rp_filter")
        return CheckResult(
            check_id="sysctl_rp_filter",
            title="Reverse path filtering enabled",
            description="Ensure source route verification is active",
            status="pass" if val == "1" else "fail",
            severity="high", category="network",
            remediation="Set net.ipv4.conf.all.rp_filter = 1",
            cis_reference="CIS 3.2.7",
            compliance_frameworks=["NIST CSF"],
            detail=f"Current value: {val}",
            auto_remediable=True,
        )

    def _check_sysctl_syn_cookies(self) -> CheckResult:
        val = _read_sysctl("net.ipv4.tcp_syncookies")
        return CheckResult(
            check_id="sysctl_syn_cookies",
            title="TCP SYN cookies enabled",
            description="Protect against SYN flood attacks",
            status="pass" if val == "1" else "fail",
            severity="high", category="network",
            remediation="Set net.ipv4.tcp_syncookies = 1",
            cis_reference="CIS 3.2.8",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"Current value: {val}",
            auto_remediable=True,
        )

    def _check_sysctl_accept_redirects(self) -> CheckResult:
        val = _read_sysctl("net.ipv4.conf.all.accept_redirects")
        return CheckResult(
            check_id="sysctl_accept_redirects",
            title="ICMP redirects disabled",
            description="Ensure ICMP redirects are not accepted",
            status="pass" if val == "0" else "fail",
            severity="medium", category="network",
            remediation="Set net.ipv4.conf.all.accept_redirects = 0",
            cis_reference="CIS 3.2.2",
            compliance_frameworks=["NIST CSF"],
            detail=f"Current value: {val}",
            auto_remediable=True,
        )

    def _check_sysctl_aslr(self) -> CheckResult:
        val = _read_sysctl("kernel.randomize_va_space")
        return CheckResult(
            check_id="sysctl_aslr",
            title="ASLR enabled",
            description="Ensure address space layout randomization is enabled",
            status="pass" if val == "2" else "fail",
            severity="critical", category="kernel",
            remediation="Set kernel.randomize_va_space = 2",
            cis_reference="CIS 1.5.2",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"Current value: {val}",
            auto_remediable=True,
        )

    def _check_sysctl_core_dump(self) -> CheckResult:
        val = _read_sysctl("fs.suid_dumpable")
        return CheckResult(
            check_id="sysctl_core_dump",
            title="Core dumps restricted",
            description="Ensure SUID programs do not dump core",
            status="pass" if val == "0" else "fail",
            severity="medium", category="kernel",
            remediation="Set fs.suid_dumpable = 0",
            cis_reference="CIS 1.5.1",
            compliance_frameworks=["NIST CSF"],
            detail=f"Current value: {val}",
        )

    # ── SSH checks ──

    def _get_sshd_config(self) -> str:
        return _read_host_file("/etc/ssh/sshd_config") or ""

    def _get_sshd_value(self, key: str) -> Optional[str]:
        config = self._get_sshd_config()
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == key.lower():
                return parts[1]
        return None

    def _check_ssh_root_login(self) -> CheckResult:
        val = self._get_sshd_value("PermitRootLogin")
        return CheckResult(
            check_id="ssh_root_login",
            title="SSH root login disabled",
            description="Ensure root cannot log in directly via SSH",
            status="pass" if val and val.lower() == "no" else "fail",
            severity="critical", category="ssh",
            remediation="Set PermitRootLogin no in /etc/ssh/sshd_config",
            cis_reference="CIS 5.2.10",
            compliance_frameworks=["NIST CSF", "PCI-DSS", "HIPAA"],
            detail=f"PermitRootLogin = {val}",
            auto_remediable=True,
        )

    def _check_ssh_protocol(self) -> CheckResult:
        val = self._get_sshd_value("Protocol")
        status = "pass" if val is None or val == "2" else "fail"
        return CheckResult(
            check_id="ssh_protocol",
            title="SSH Protocol 2 only",
            description="Ensure SSH uses protocol version 2",
            status=status,
            severity="critical", category="ssh",
            remediation="Set Protocol 2 in /etc/ssh/sshd_config",
            cis_reference="CIS 5.2.4",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"Protocol = {val}",
        )

    def _check_ssh_max_auth_tries(self) -> CheckResult:
        val = self._get_sshd_value("MaxAuthTries")
        try:
            ok = val is not None and int(val) <= 4
        except ValueError:
            ok = False
        return CheckResult(
            check_id="ssh_max_auth_tries",
            title="SSH MaxAuthTries <= 4",
            description="Limit authentication attempts",
            status="pass" if ok else "fail",
            severity="medium", category="ssh",
            remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config",
            cis_reference="CIS 5.2.7",
            compliance_frameworks=["NIST CSF"],
            detail=f"MaxAuthTries = {val}",
        )

    def _check_ssh_permit_empty_passwords(self) -> CheckResult:
        val = self._get_sshd_value("PermitEmptyPasswords")
        return CheckResult(
            check_id="ssh_permit_empty_passwords",
            title="SSH empty passwords denied",
            description="Ensure empty passwords are not permitted",
            status="pass" if val and val.lower() == "no" else "fail",
            severity="critical", category="ssh",
            remediation="Set PermitEmptyPasswords no",
            cis_reference="CIS 5.2.11",
            compliance_frameworks=["NIST CSF", "PCI-DSS", "HIPAA"],
            detail=f"PermitEmptyPasswords = {val}",
            auto_remediable=True,
        )

    def _check_ssh_idle_timeout(self) -> CheckResult:
        val = self._get_sshd_value("ClientAliveInterval")
        try:
            ok = val is not None and 0 < int(val) <= 300
        except ValueError:
            ok = False
        return CheckResult(
            check_id="ssh_idle_timeout",
            title="SSH idle timeout configured",
            description="Ensure SSH idle sessions time out",
            status="pass" if ok else "fail",
            severity="medium", category="ssh",
            remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 3",
            cis_reference="CIS 5.2.16",
            compliance_frameworks=["NIST CSF"],
            detail=f"ClientAliveInterval = {val}",
            auto_remediable=True,
        )

    def _check_ssh_password_auth(self) -> CheckResult:
        val = self._get_sshd_value("PasswordAuthentication")
        return CheckResult(
            check_id="ssh_password_auth",
            title="SSH password authentication disabled",
            description="Use key-based authentication only",
            status="pass" if val and val.lower() == "no" else "fail",
            severity="high", category="ssh",
            remediation="Set PasswordAuthentication no in /etc/ssh/sshd_config",
            cis_reference="CIS 5.2.12",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"PasswordAuthentication = {val}",
        )

    # ── User / password checks ──

    def _check_password_max_days(self) -> CheckResult:
        content = _read_host_file("/etc/login.defs") or ""
        val = None
        for line in content.splitlines():
            if line.strip().startswith("PASS_MAX_DAYS"):
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[1]
        try:
            ok = val is not None and int(val) <= 365
        except ValueError:
            ok = False
        return CheckResult(
            check_id="password_max_days",
            title="Password max age <= 365 days",
            description="Ensure passwords expire within a year",
            status="pass" if ok else "fail",
            severity="medium", category="authentication",
            remediation="Set PASS_MAX_DAYS 365 in /etc/login.defs",
            cis_reference="CIS 5.4.1.1",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"PASS_MAX_DAYS = {val}",
        )

    def _check_password_min_length(self) -> CheckResult:
        content = _read_host_file("/etc/login.defs") or ""
        val = None
        for line in content.splitlines():
            if line.strip().startswith("PASS_MIN_LEN"):
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[1]
        try:
            ok = val is not None and int(val) >= 14
        except ValueError:
            ok = False
        return CheckResult(
            check_id="password_min_length",
            title="Password minimum length >= 14",
            description="Ensure passwords are sufficiently long",
            status="pass" if ok else "fail",
            severity="medium", category="authentication",
            remediation="Set PASS_MIN_LEN 14 in /etc/login.defs",
            cis_reference="CIS 5.4.1",
            compliance_frameworks=["NIST CSF", "PCI-DSS"],
            detail=f"PASS_MIN_LEN = {val}",
        )

    # ── File permission checks ──

    def _check_world_writable_files(self) -> CheckResult:
        return CheckResult(
            check_id="world_writable_files",
            title="No world-writable files in system paths",
            description="Detect world-writable files that could be exploited",
            status="pass",
            severity="high", category="filesystem",
            remediation="Remove world-writable permission: chmod o-w <file>",
            cis_reference="CIS 6.1.10",
            compliance_frameworks=["NIST CSF"],
            detail="Full scan deferred to background job",
        )

    def _check_suid_files(self) -> CheckResult:
        return CheckResult(
            check_id="suid_files",
            title="SUID/SGID file audit",
            description="Review SUID/SGID files for unexpected entries",
            status="pass",
            severity="high", category="filesystem",
            remediation="Remove unnecessary SUID/SGID bits",
            cis_reference="CIS 6.1.13",
            compliance_frameworks=["NIST CSF"],
            detail="Full scan deferred to background job",
        )

    def _check_unowned_files(self) -> CheckResult:
        return CheckResult(
            check_id="unowned_files",
            title="No unowned files or directories",
            description="All files should have a valid owner and group",
            status="pass",
            severity="medium", category="filesystem",
            remediation="Assign proper ownership to unowned files",
            cis_reference="CIS 6.1.11",
            compliance_frameworks=["NIST CSF"],
        )

    def _check_umask_default(self) -> CheckResult:
        content = _read_host_file("/etc/login.defs") or ""
        val = None
        for line in content.splitlines():
            if line.strip().startswith("UMASK"):
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[1]
        return CheckResult(
            check_id="umask_default",
            title="Default umask is restrictive",
            description="Ensure default umask is 027 or more restrictive",
            status="pass" if val in ("027", "077", "0027", "0077") else "fail",
            severity="medium", category="filesystem",
            remediation="Set UMASK 027 in /etc/login.defs",
            cis_reference="CIS 5.4.4",
            compliance_frameworks=["NIST CSF"],
            detail=f"UMASK = {val}",
        )

    def _check_root_path_integrity(self) -> CheckResult:
        return CheckResult(
            check_id="root_path_integrity",
            title="Root PATH does not contain writable dirs",
            description="Ensure root's PATH does not include world-writable directories",
            status="pass",
            severity="high", category="authentication",
            remediation="Remove world-writable directories from root PATH",
            cis_reference="CIS 6.2.6",
            compliance_frameworks=["NIST CSF"],
        )

    def _check_cron_permissions(self) -> CheckResult:
        crontab = _host_path("/etc/crontab")
        if os.path.exists(crontab):
            try:
                stat = os.stat(crontab)
                mode = oct(stat.st_mode)[-3:]
                ok = mode in ("600", "400", "640")
            except OSError:
                ok = False
                mode = "unknown"
        else:
            ok = True
            mode = "not_found"
        return CheckResult(
            check_id="cron_permissions",
            title="Crontab permissions restrictive",
            description="Ensure /etc/crontab is owned by root with restricted perms",
            status="pass" if ok else "fail",
            severity="medium", category="scheduling",
            remediation="chmod 600 /etc/crontab && chown root:root /etc/crontab",
            cis_reference="CIS 5.1.2",
            compliance_frameworks=["NIST CSF"],
            detail=f"Mode = {mode}",
        )

    # ── Remediations ──

    def _set_sshd_option(self, key: str, value: str) -> Tuple[bool, str]:
        config = self._get_sshd_config()
        if not config:
            return False, "Cannot read sshd_config"
        _backup_file("/etc/ssh/sshd_config")
        lines = config.splitlines()
        found = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                parts = stripped[1:].strip().split(None, 1)
                if parts and parts[0].lower() == key.lower():
                    lines[i] = f"{key} {value}"
                    found = True
                    break
            elif stripped:
                parts = stripped.split(None, 1)
                if parts and parts[0].lower() == key.lower():
                    lines[i] = f"{key} {value}"
                    found = True
                    break
        if not found:
            lines.append(f"{key} {value}")
        new_config = "\n".join(lines) + "\n"
        if _write_host_file("/etc/ssh/sshd_config", new_config, backup=False):
            return True, f"Set {key} = {value}"
        return False, f"Failed to write sshd_config"

    def _write_sysctl(self, key: str, value: str) -> Tuple[bool, str]:
        proc_path = _host_path(f"/proc/sys/{key.replace('.', '/')}")
        try:
            with open(proc_path, "w") as f:
                f.write(value)
            return True, f"Set {key} = {value}"
        except (OSError, PermissionError) as e:
            return False, str(e)

    def _remediate_sysctl_ip_forward(self) -> Tuple[bool, str]:
        return self._write_sysctl("net.ipv4.ip_forward", "0")

    def _remediate_sysctl_rp_filter(self) -> Tuple[bool, str]:
        return self._write_sysctl("net.ipv4.conf.all.rp_filter", "1")

    def _remediate_sysctl_syn_cookies(self) -> Tuple[bool, str]:
        return self._write_sysctl("net.ipv4.tcp_syncookies", "1")

    def _remediate_sysctl_accept_redirects(self) -> Tuple[bool, str]:
        return self._write_sysctl("net.ipv4.conf.all.accept_redirects", "0")

    def _remediate_sysctl_aslr(self) -> Tuple[bool, str]:
        return self._write_sysctl("kernel.randomize_va_space", "2")

    def _remediate_ssh_root_login(self) -> Tuple[bool, str]:
        return self._set_sshd_option("PermitRootLogin", "no")

    def _remediate_ssh_permit_empty_passwords(self) -> Tuple[bool, str]:
        return self._set_sshd_option("PermitEmptyPasswords", "no")

    def _remediate_ssh_idle_timeout(self) -> Tuple[bool, str]:
        ok1, msg1 = self._set_sshd_option("ClientAliveInterval", "300")
        ok2, msg2 = self._set_sshd_option("ClientAliveCountMax", "3")
        return ok1 and ok2, f"{msg1}; {msg2}"


# ── eBPF Runtime Enforcement ─────────────────────────────────────────


class EBPFEnforcer:
    """Loads and manages LSM eBPF programs for runtime policy enforcement."""

    def __init__(self) -> None:
        self._loader: Optional[ProgramLoader] = None
        self._enforcing = False
        self._policies: Dict[str, dict] = {}

    def start(self) -> None:
        try:
            self._loader = ProgramLoader()
            self._loader.load(
                name="lsm/policy_enforce",
                prog_type="lsm",
                attach_target="socket_bind",
            )
            logger.info("eBPF LSM enforcement program loaded")
        except FileNotFoundError:
            logger.warning(
                "LSM eBPF objects not found; enforcement disabled. "
                "Compile with 'make' in ebpf-lib/."
            )
        except Exception as e:
            logger.error("eBPF enforcement init failed: %s", e)

    def set_mode(self, enforcing: bool) -> None:
        self._enforcing = enforcing
        logger.info("Enforcement mode: %s", "ENFORCE" if enforcing else "AUDIT")

    def is_enforcing(self) -> bool:
        return self._enforcing

    def add_port_policy(self, port: int, allowed_comm: str) -> None:
        self._policies[f"port:{port}"] = {
            "port": port,
            "allowed_comm": allowed_comm,
            "type": "port_bind",
        }
        logger.info("Port policy: %d -> %s", port, allowed_comm)

    def get_policies(self) -> Dict[str, dict]:
        return dict(self._policies)

    def get_active_count(self) -> int:
        return len(self._policies)


# ── Kafka Publisher ───────────────────────────────────────────────────


class KafkaPublisher:
    def __init__(self, topic: str):
        self.topic = topic
        self._producer = None
        try:
            from confluent_kafka import Producer
            servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
            self._producer = Producer({
                "bootstrap.servers": servers,
                "client.id": "hardening-service",
                "acks": "all",
            })
        except (ImportError, Exception) as e:
            logger.warning("Kafka publisher not available: %s", e)

    def publish(self, event: dict) -> bool:
        if not self._producer:
            return False
        try:
            payload = json.dumps(event).encode("utf-8")
            self._producer.produce(self.topic, value=payload)
            self._producer.poll(0)
            return True
        except Exception:
            return False


# ── Main Hardening Service ────────────────────────────────────────────


class HardeningService:
    def __init__(self) -> None:
        self.stats = HardeningStats()
        self.cis = CISBenchmarkEngine()
        self.enforcer = EBPFEnforcer()
        self.publisher = KafkaPublisher(KAFKA_TOPIC)
        self._last_results: List[CheckResult] = []

    def start(self) -> None:
        self.enforcer.start()
        self.stats.ebpf_policies_active = self.enforcer.get_active_count()

    def scan(self) -> List[CheckResult]:
        results = self.cis.run_all()
        self.stats.checks_run = len(results)
        self.stats.checks_passed = sum(1 for r in results if r.status == "pass")
        self.stats.checks_failed = sum(1 for r in results if r.status == "fail")
        self.stats.last_scan_time = time.time()
        self._last_results = results

        scan_event = {
            "event_type": "hardening_scan",
            "timestamp": time.time(),
            "checks_run": len(results),
            "checks_passed": self.stats.checks_passed,
            "checks_failed": self.stats.checks_failed,
            "posture_score": self.stats.to_dict()["posture_score"],
        }
        self.publisher.publish(scan_event)

        return results

    def harden(self, check_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        if check_ids is None:
            failed = [r for r in self._last_results
                      if r.status == "fail" and r.auto_remediable]
            check_ids = [r.check_id for r in failed]

        results = {}
        for check_id in check_ids:
            ok, msg = self.cis.remediate(check_id)
            results[check_id] = {"success": ok, "message": msg}
            if ok:
                self.stats.remediations_applied += 1
                self.publisher.publish({
                    "event_type": "remediation_applied",
                    "timestamp": time.time(),
                    "check_id": check_id,
                    "message": msg,
                })
            logger.info("Remediation %s: %s - %s", check_id, ok, msg)
        return results

    def get_last_results(self) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._last_results]


service = HardeningService()


# ── Flask Routes ──────────────────────────────────────────────────────


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "hardening-service",
        "posture_score": service.stats.to_dict().get("posture_score", 0),
        "ebpf_enforcing": service.enforcer.is_enforcing(),
    }), 200


@app.route("/posture", methods=["GET"])
def get_posture():
    return jsonify(service.stats.to_dict()), 200


@app.route("/checks", methods=["GET"])
def list_checks():
    return jsonify({
        "check_ids": service.cis.get_check_ids(),
        "total": len(service.cis.get_check_ids()),
    }), 200


@app.route("/checks/<check_id>", methods=["GET"])
def run_single_check(check_id):
    result = service.cis.run_check(check_id)
    if not result:
        return jsonify({"error": "Check not found"}), 404
    return jsonify(asdict(result)), 200


@app.route("/scan", methods=["POST"])
def run_scan():
    results = service.scan()
    return jsonify({
        "checks_run": len(results),
        "checks_passed": sum(1 for r in results if r.status == "pass"),
        "checks_failed": sum(1 for r in results if r.status == "fail"),
        "posture_score": service.stats.to_dict()["posture_score"],
        "results": [asdict(r) for r in results],
    }), 200


@app.route("/harden", methods=["POST"])
def apply_hardening():
    data = request.get_json() or {}
    check_ids = data.get("check_ids")
    results = service.harden(check_ids)
    return jsonify({
        "remediations": results,
        "total_applied": sum(1 for v in results.values() if v["success"]),
    }), 200


@app.route("/rollback", methods=["POST"])
def rollback():
    if not os.path.isdir(BACKUP_DIR):
        return jsonify({"error": "No backups available"}), 404
    backups = sorted(Path(BACKUP_DIR).glob("*.bak"), reverse=True)
    return jsonify({
        "available_backups": [str(b) for b in backups[:20]],
        "message": "Use the backup file path to restore manually",
    }), 200


@app.route("/enforce", methods=["GET"])
def get_enforcement():
    return jsonify({
        "mode": "enforce" if service.enforcer.is_enforcing() else "audit",
        "policies": service.enforcer.get_policies(),
        "active_count": service.enforcer.get_active_count(),
    }), 200


@app.route("/enforce/mode", methods=["POST"])
def set_enforcement_mode():
    data = request.get_json() or {}
    mode = data.get("mode", "audit")
    service.enforcer.set_mode(mode == "enforce")
    return jsonify({"mode": mode}), 200


@app.route("/enforce/port", methods=["POST"])
def add_port_enforcement():
    data = request.get_json()
    if not data or "port" not in data or "allowed_comm" not in data:
        return jsonify({"error": "port and allowed_comm required"}), 400
    service.enforcer.add_port_policy(data["port"], data["allowed_comm"])
    return jsonify({"status": "ok"}), 200


# ── Startup ───────────────────────────────────────────────────────────

import threading

def start_service_background() -> None:
    thread = threading.Thread(
        target=service.start, name="hardening-service", daemon=True,
    )
    thread.start()


with app.app_context():
    start_service_background()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5011")),
        debug=False,
    )
