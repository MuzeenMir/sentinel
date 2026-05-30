#!/usr/bin/env python3
"""Publish one day's signed Merkle root for the SENTINEL audit ledger (wedge #3).

Run nightly by ``.github/workflows/merkle-root-publish.yml`` with a privileged
read role (it must see all tenants' rows — the chain is global). Reuses the
unit-tested pure functions from ``verify_audit_chain``; the only logic here is
I/O (fetch rows, pick the target day, write JSON), so it is left uncovered.

The whole chain is recomputed from all rows each run so ``prev_root`` linkage is
always correct; revisit with an incremental cursor if row volume demands it.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))

from verify_audit_chain import (  # noqa: E402
    chain_roots,
    compute_daily_roots,
    fetch_rows,
)


def main(argv=None) -> int:  # pragma: no cover
    parser = argparse.ArgumentParser(description="Publish a daily audit Merkle root.")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("AUDIT_DATABASE_URL") or os.environ.get("DATABASE_URL"),
    )
    parser.add_argument(
        "--date",
        default=(datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d"),
        help="UTC date (YYYY-MM-DD) to publish; defaults to yesterday.",
    )
    parser.add_argument(
        "--out-dir", default=os.environ.get("AUDIT_ROOTS_DIR", "audit-roots")
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        print("ERROR: --database-url or DATABASE_URL required", file=sys.stderr)
        return 2

    chained = chain_roots(compute_daily_roots(fetch_rows(args.database_url)))
    entry = next((c for c in chained if c["date"] == args.date), None)
    if entry is None:
        print(f"No audit rows for {args.date}; nothing to publish.")
        return 0

    entry["generated_at"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"{args.date}.json")
    with open(out_path, "w") as fh:
        json.dump(entry, fh, indent=2, sort_keys=True)
    print(f"Wrote {out_path}: root={entry['root'][:16]}… count={entry['count']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
