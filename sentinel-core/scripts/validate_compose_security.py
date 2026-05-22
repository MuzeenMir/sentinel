#!/usr/bin/env python3
"""Validate docker-compose security invariants for Phase 0."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
INSTALLER = ROOT / "agent" / "install.sh"
API_GATEWAY_TEST = ROOT / "backend" / "tests" / "test_api_gateway.py"

FORBIDDEN_DEFAULTS = [
    "POSTGRES_PASSWORD:-",
    "JWT_SECRET_KEY:-",
    "ADMIN_PASSWORD:-",
    "GRAFANA_PASSWORD:-",
    "INTERNAL_SERVICE_TOKEN:-",
    "change-this-in-production",
    "ChangeMe!2026",
    "sentinel_password",
    "GRAFANA_PASSWORD:-sentinel",
]

REQUIRED_SECRETS = {
    "POSTGRES_PASSWORD",
    "JWT_SECRET_KEY",
    "ADMIN_PASSWORD",
    "GRAFANA_PASSWORD",
    "INTERNAL_SERVICE_TOKEN",
}

FORBIDDEN_FALLBACK_SECRET_NAMES = REQUIRED_SECRETS | {
    "JWT_SECRET",
    "DATABASE_PASSWORD",
    "REDIS_PASSWORD",
    "AGENT_TOKEN",
}

INTERNAL_SERVICES = {
    "postgres",
    "redis",
    "db-migrate",
    "zookeeper",
    "kafka",
    "auth-service",
    "data-collector",
    "xdp-collector",
    "alert-service",
    "ai-engine",
    "elasticsearch",
    "kibana",
    "policy-orchestrator",
    "drl-engine",
    "xai-service",
    "compliance-engine",
    "hids-agent",
    "hardening-service",
    "prometheus",
    "grafana",
    "flink-anomaly-detection",
    "flink-feature-extraction",
    "flink-drl-feed",
}

PUBLIC_SERVICES = {"api-gateway", "admin-console", "tempo"}

# Services permitted to run privileged: true (genuine kernel-attach needs).
PRIVILEGED_ALLOWED = {"xdp-collector", "hardening-service"}

SYSTEMD_HARDENING_FLAGS = (
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "PrivateTmp=true",
)


def service_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    in_services = False
    for line in text.splitlines():
        if re.match(r"^[a-zA-Z0-9_-]+:\s*$", line):
            in_services = line == "services:"
            current = None
            continue

        if not in_services:
            continue

        match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            blocks[current] = [line]
            continue
        if current is not None:
            blocks[current].append(line)
    return {name: "\n".join(lines) for name, lines in blocks.items()}


def port_entries(block: str) -> list[str]:
    entries: list[str] = []
    in_ports = False
    for line in block.splitlines():
        inline_ports = re.match(r"^    ports:\s*\[(?P<ports>.*)]\s*$", line)
        if inline_ports:
            entries.extend(
                port.strip().strip("\"'")
                for port in inline_ports.group("ports").split(",")
            )
            in_ports = False
            continue

        if re.match(r"^    [a-zA-Z0-9_-]+:\s*", line):
            in_ports = bool(re.match(r"^    ports:\s*(?:#.*)?$", line))
            continue

        if not in_ports:
            continue

        port = re.match(r"^      -\s*(?P<port>.+?)\s*$", line)
        if port:
            entries.append(port.group("port").strip().strip("\"'"))

    return entries


def check_secret_fallbacks(text: str, errors: list[str]) -> None:
    for secret in sorted(FORBIDDEN_FALLBACK_SECRET_NAMES):
        if re.search(rf"\$\{{{re.escape(secret)}:-[^}}]+}}", text):
            errors.append(f"{secret} must not define a default fallback")


def check_auth_lockout_env(blocks: dict[str, str], errors: list[str]) -> None:
    auth_block = blocks.get("auth-service", "")
    has_lockout_threshold = re.search(
        r"^\s*(?:-\s*)?LOCKOUT_THRESHOLD\s*=",
        auth_block,
        flags=re.MULTILINE,
    )
    if not has_lockout_threshold:
        errors.append("auth-service must declare LOCKOUT_THRESHOLD")


def check_installer(errors: list[str]) -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    if "sha256sum" not in text:
        errors.append("agent installer must verify downloads with sha256sum")
    if "https://" not in text:
        errors.append("agent installer must require https:// downloads")
    for flag in SYSTEMD_HARDENING_FLAGS:
        if flag not in text:
            errors.append(f"agent installer systemd unit must set {flag}")


def check_api_gateway_tests(errors: list[str]) -> None:
    text = API_GATEWAY_TEST.read_text(encoding="utf-8")
    if "def test_viewer_cannot" not in text:
        errors.append("api-gateway tests must include viewer forbidden coverage")


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    errors: list[str] = []
    blocks = service_blocks(text)

    for token in FORBIDDEN_DEFAULTS:
        if token in text:
            errors.append(f"forbidden compose default found: {token}")

    check_secret_fallbacks(text, errors)

    for secret in sorted(REQUIRED_SECRETS):
        required_syntax = f"${{{secret}:?set {secret}}}"
        if required_syntax not in text:
            errors.append(f"{secret} must use non-empty required-variable syntax")

        for match in re.finditer(rf"\$\{{{secret}[^}}]*\}}", text):
            if match.group(0) != required_syntax:
                errors.append(f"{secret} must use non-empty required-variable syntax")
                break

    check_auth_lockout_env(blocks, errors)
    check_installer(errors)
    check_api_gateway_tests(errors)

    for name, block in blocks.items():
        ports = port_entries(block)
        has_ports = re.search(
            r"^    ports:\s*(?:#.*|\S.*)?$", block, flags=re.MULTILINE
        )
        if name in INTERNAL_SERVICES and has_ports:
            errors.append(f"internal service exposes host ports: {name}")
        if name in INTERNAL_SERVICES:
            for port in ports:
                if port.startswith("0.0.0.0:"):
                    errors.append(
                        f"internal service publishes 0.0.0.0 host port: {name}"
                    )
                    break
        if name not in INTERNAL_SERVICES | PUBLIC_SERVICES:
            errors.append(f"unclassified compose service: {name}")
        has_host_network = re.search(
            r"^    network_mode:\s*['\"]?host['\"]?\s*$", block, flags=re.MULTILINE
        )
        if has_host_network:
            errors.append(f"host network mode is forbidden: {name}")
        has_privileged = re.search(
            r"^\s*privileged:\s*true\s*$", block, flags=re.MULTILINE
        )
        if has_privileged and name not in PRIVILEGED_ALLOWED:
            errors.append(f"privileged mode is not allowed: {name}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("compose security validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
