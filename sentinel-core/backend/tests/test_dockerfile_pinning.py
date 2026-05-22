"""Regression check: backend Dockerfile base images must be digest-pinned."""

from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _dockerfiles():
    return sorted(BACKEND.glob("*/Dockerfile"))


def test_backend_dockerfiles_present():
    assert _dockerfiles(), "no backend Dockerfiles found"


def test_backend_base_images_are_digest_pinned():
    unpinned = []
    for dockerfile in _dockerfiles():
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM ") and "@sha256:" not in line:
                unpinned.append(f"{dockerfile.relative_to(BACKEND)}: {line}")
    assert not unpinned, "unpinned base images:\n" + "\n".join(unpinned)
