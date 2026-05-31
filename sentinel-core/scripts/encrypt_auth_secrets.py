#!/usr/bin/env python3
"""Backfill: encrypt existing plaintext ``users.mfa_secret`` at rest (T-027).

Idempotent — rows already enveloped (``v1:``) are skipped. Run once after the
``20260530_002_mfa_secret_text`` migration and the encryption wiring deploy.
Requires ``SENTINEL_SECRET_KEK``.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from secret_crypto import encrypt  # noqa: E402


def needs_encryption(value) -> bool:
    """A non-null secret that is not already a v1: envelope must be encrypted."""
    return value is not None and not value.startswith("v1:")


def main(argv=None) -> int:  # pragma: no cover
    parser = argparse.ArgumentParser(description="Encrypt plaintext MFA secrets.")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not args.database_url:
        print("ERROR: --database-url or DATABASE_URL required", file=sys.stderr)
        return 2

    import psycopg2

    conn = psycopg2.connect(args.database_url)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, mfa_secret FROM users WHERE mfa_secret IS NOT NULL")
        targets = [(uid, sec) for uid, sec in cur.fetchall() if needs_encryption(sec)]
        for uid, secret in targets:
            if args.dry_run:
                print(f"[dry-run] would encrypt user {uid}")
            else:
                cur.execute(
                    "UPDATE users SET mfa_secret = %s WHERE id = %s",
                    (encrypt(secret), uid),
                )
        if not args.dry_run:
            conn.commit()
        verb = "Would encrypt" if args.dry_run else "Encrypted"
        print(f"{verb} {len(targets)} mfa_secret row(s).")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
