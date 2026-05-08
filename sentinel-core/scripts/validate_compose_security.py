#!/usr/bin/env python3
"""Validate docker-compose security invariants for Phase 0."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"

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

HOST_NETWORK_ALLOWED_PROFILES = {"xdp"}
HOST_NETWORK_DEPENDENCY_ENV = {
    "AUTH_SERVICE_URL",
    "KAFKA_BOOTSTRAP_SERVERS",
}
LOCALHOST_DEPENDENCY_RE = re.compile(r"(?:^|[/:,@])(?:localhost|127\.0\.0\.1)(?::|/|$)")


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


def has_allowed_host_network_profile(block: str) -> bool:
    inline_profiles = re.search(r"^    profiles:\s*\[(?P<profiles>.*)\]\s*$", block, flags=re.MULTILINE)
    if inline_profiles:
        profiles = {
            profile.strip().strip("\"'")
            for profile in inline_profiles.group("profiles").split(",")
        }
        return bool(profiles & HOST_NETWORK_ALLOWED_PROFILES)

    profiles: set[str] = set()
    in_profiles = False
    for line in block.splitlines():
        if re.match(r"^    [a-zA-Z0-9_-]+:\s*$", line):
            in_profiles = line == "    profiles:"
            continue

        if not in_profiles:
            continue

        profile = re.match(r"^      - ['\"]?(?P<profile>[a-zA-Z0-9_-]+)['\"]?\s*$", line)
        if profile:
            profiles.add(profile.group("profile"))

    return bool(profiles & HOST_NETWORK_ALLOWED_PROFILES)


def host_network_localhost_dependencies(block: str) -> list[str]:
    stale_dependencies: list[str] = []
    for key in sorted(HOST_NETWORK_DEPENDENCY_ENV):
        patterns = [
            rf"^\s+-\s*{re.escape(key)}=(?P<value>\S.*)$",
            rf"^\s*{re.escape(key)}:\s*['\"]?(?P<value>[^'\"]\S*)['\"]?\s*$",
        ]
        for pattern in patterns:
            match = re.search(pattern, block, flags=re.MULTILINE)
            if match and LOCALHOST_DEPENDENCY_RE.search(match.group("value")):
                stale_dependencies.append(key)
                break
    return stale_dependencies


def main() -> int:
    text = COMPOSE.read_text(encoding="utf-8")
    errors: list[str] = []

    for token in FORBIDDEN_DEFAULTS:
        if token in text:
            errors.append(f"forbidden compose default found: {token}")

    for secret in sorted(REQUIRED_SECRETS):
        required_syntax = f"${{{secret}:?set {secret}}}"
        if required_syntax not in text:
            errors.append(f"{secret} must use non-empty required-variable syntax")

        for match in re.finditer(rf"\$\{{{secret}[^}}]*\}}", text):
            if match.group(0) != required_syntax:
                errors.append(f"{secret} must use non-empty required-variable syntax")
                break

    for name, block in service_blocks(text).items():
        has_ports = re.search(r"^    ports:\s*(?:#.*|\S.*)?$", block, flags=re.MULTILINE)
        if name in INTERNAL_SERVICES and has_ports:
            errors.append(f"internal service exposes host ports: {name}")
        if name not in INTERNAL_SERVICES | PUBLIC_SERVICES:
            errors.append(f"unclassified compose service: {name}")
        has_host_network = re.search(r"^    network_mode:\s*['\"]?host['\"]?\s*$", block, flags=re.MULTILINE)
        if has_host_network and not has_allowed_host_network_profile(block):
            errors.append(f"host network service must be behind an explicit profile: {name}")
        if has_host_network:
            for dependency in host_network_localhost_dependencies(block):
                errors.append(f"host network service uses localhost dependency {dependency}: {name}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("compose security validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
