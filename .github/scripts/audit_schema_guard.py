#!/usr/bin/env python3
"""Fail-closed two-person guard for audit schema and RLS changes."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REVIEWED_TRAILER = "Audit-Reviewed-by"
APPROVED_TRAILER = "Audit-Approved-by"
RLS_PATTERNS = (
    re.compile(r"\bROW\s+LEVEL\s+SECURITY\b", re.IGNORECASE),
    re.compile(r"\bCREATE\s+POLICY\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class GuardResult:
    exit_code: int
    messages: list[str]


def evaluate_guard(
    *,
    changed_files: list[str],
    diff_text: str,
    pr_body: str,
) -> GuardResult:
    matched_files = find_guarded_files(changed_files, diff_text)

    if not matched_files:
        return GuardResult(
            0,
            ["no audit-schema/RLS changes — guard not applicable"],
        )

    messages = ["audit-schema/RLS changes matched:"]
    messages.extend(f"- {path}" for path in matched_files)

    trailers = parse_trailers(pr_body)
    reviewed_by = trailers.get(REVIEWED_TRAILER)
    approved_by = trailers.get(APPROVED_TRAILER)
    errors: list[str] = []

    if not reviewed_by:
        errors.append(f"missing trailer: {REVIEWED_TRAILER}")
    if not approved_by:
        errors.append(f"missing trailer: {APPROVED_TRAILER}")
    if reviewed_by and approved_by and reviewed_by.casefold() == approved_by.casefold():
        errors.append(
            f"{REVIEWED_TRAILER} and {APPROVED_TRAILER} must be two different people"
        )

    if errors:
        return GuardResult(1, messages + errors)

    messages.append("audit-schema/RLS guard satisfied")
    return GuardResult(0, messages)


def find_guarded_files(changed_files: list[str], diff_text: str) -> list[str]:
    matched: set[str] = set()
    for path in changed_files:
        normalized = path.strip()
        if not normalized:
            continue
        if normalized.startswith("sentinel-core/backend/migrations/"):
            matched.add(normalized)
        if "audit" in normalized.casefold():
            matched.add(normalized)

    matched.update(find_rls_files(diff_text))
    return sorted(matched)


def find_rls_files(diff_text: str) -> set[str]:
    matched: set[str] = set()
    current_file: str | None = None

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file = _parse_diff_file(line)
            continue
        if current_file is None:
            continue
        if not line.startswith(("+", "-")) or line.startswith(("+++", "---")):
            continue
        if any(pattern.search(line) for pattern in RLS_PATTERNS):
            matched.add(current_file)

    return matched


def parse_trailers(pr_body: str) -> dict[str, str]:
    trailers: dict[str, str] = {}
    for trailer in (REVIEWED_TRAILER, APPROVED_TRAILER):
        match = re.search(
            rf"^{re.escape(trailer)}:\s*(?P<name>\S.*)$",
            pr_body,
            flags=re.MULTILINE,
        )
        if match:
            trailers[trailer] = match.group("name").strip()
    return trailers


def _parse_diff_file(line: str) -> str | None:
    match = re.match(r"diff --git a/(?P<old>.+?) b/(?P<new>.+)$", line)
    if not match:
        return None
    return match.group("new")


def read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed-files", type=Path, required=True)
    parser.add_argument("--diff-file", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    args = parser.parse_args(argv)

    result = evaluate_guard(
        changed_files=read_lines(args.changed_files),
        diff_text=args.diff_file.read_text(encoding="utf-8"),
        pr_body=args.body_file.read_text(encoding="utf-8"),
    )
    stream = sys.stderr if result.exit_code else sys.stdout
    for message in result.messages:
        print(message, file=stream)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
