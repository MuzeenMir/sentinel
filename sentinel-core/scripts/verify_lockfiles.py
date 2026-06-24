#!/usr/bin/env python3
"""Verify per-service hashed lockfiles (audit CI-07 / Wave B4).

Each backend service that ships in a container has a human-edited
``requirements.txt`` (loose ``>=`` pins, the source of truth) and a generated
``requirements.lock`` (fully pinned ``==`` + ``--generate-hashes``) that the
Dockerfile installs with ``pip install --require-hashes``. This check is the
gate that keeps the two from silently drifting and the lock from losing its
supply-chain teeth. It asserts, for every ``requirements.lock`` under
``sentinel-core/backend/*/``:

1. a sibling ``requirements.txt`` exists;
2. every requirement in the lock is exact-pinned (``==``) and carries at least
   one ``--hash=sha256:`` (so ``pip install --require-hashes`` accepts it);
3. every *direct* dependency named in ``requirements.txt`` is present in the
   lock — except packages the lock header records as deliberately excluded via
   ``--no-emit-package`` (e.g. ``torch``, installed separately from the PyTorch
   CPU index).

It does **not** recompile against the live index, so it never false-fails when
an upstream release lands between commit and CI; the committed lock is the
artifact under review. Regenerate a lock with the exact command its header
records (``uv pip compile requirements.txt --generate-hashes ...``).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Repo-root-relative directory holding the per-service trees.
BACKEND_GLOB = "sentinel-core/backend/*/requirements.lock"

# A lock requirement block starts at column 0 with "<name>[extras]==<version>".
_PKG_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(?P<ver>\S+)"
)
_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")
_NOEMIT_RE = re.compile(r"--no-emit-package[=\s]+([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    """PEP 503 normalized distribution name (Flask_CORS -> flask-cors)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_txt_direct_deps(path: Path) -> list[str]:
    """Direct (top-level) dependency names from a requirements.txt."""
    deps: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # skip blanks, comments, -r/-c/--flags
            continue
        line = line.split(";", 1)[0].strip()  # drop env markers
        # name ends at the first extras bracket or version operator.
        name = re.split(r"[\[<>=!~ ]", line, 1)[0].strip()
        if name:
            deps.append(normalize(name))
    return deps


def parse_lock(path: Path) -> tuple[dict[str, list[str]], set[str]]:
    """Return ({normalized_name: [hashes]}, {no_emit_excluded_names})."""
    pkgs: dict[str, list[str]] = {}
    excluded: set[str] = set()
    current: str | None = None
    for raw in path.read_text().splitlines():
        if raw.startswith("#"):  # header / annotation comments
            for m in _NOEMIT_RE.finditer(raw):
                excluded.add(normalize(m.group(1)))
            continue
        m = _PKG_RE.match(raw)
        if m:
            current = normalize(m.group("name"))
            pkgs.setdefault(current, [])
            for h in _HASH_RE.findall(raw):
                pkgs[current].append(h)
            continue
        if current is not None:
            for h in _HASH_RE.findall(raw):
                pkgs[current].append(h)
    return pkgs, excluded


def verify_service(lock_path: Path) -> list[str]:
    """Return a list of human-readable problems for one service (empty == ok)."""
    problems: list[str] = []
    svc = lock_path.parent.name
    txt_path = lock_path.parent / "requirements.txt"

    if not txt_path.exists():
        return [f"{svc}: requirements.lock present but requirements.txt missing"]

    pkgs, excluded = parse_lock(lock_path)
    if not pkgs:
        return [f"{svc}: requirements.lock has no pinned requirements"]

    for name, hashes in pkgs.items():
        if not hashes:
            problems.append(
                f"{svc}: '{name}' in lock has no --hash= (require-hashes would reject it)"
            )

    for dep in parse_txt_direct_deps(txt_path):
        if dep in excluded:
            continue
        if dep not in pkgs:
            problems.append(
                f"{svc}: direct dep '{dep}' in requirements.txt is absent from "
                f"requirements.lock — regenerate the lock (see its header command)"
            )
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    locks = sorted(root.glob(BACKEND_GLOB))
    if not locks:
        print(f"ERROR: no lockfiles found under {root}/{BACKEND_GLOB}", file=sys.stderr)
        return 1

    all_problems: list[str] = []
    for lock in locks:
        all_problems.extend(verify_service(lock))

    if all_problems:
        print("Lockfile verification FAILED:", file=sys.stderr)
        for p in all_problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(locks)} service lockfiles verified (pinned + hashed + cover their requirements.txt)."
    )
    for lock in locks:
        print(f"  - {lock.parent.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
