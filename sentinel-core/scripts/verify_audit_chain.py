#!/usr/bin/env python3
"""Independent verifier for the SENTINEL tamper-evident audit ledger (wedge #3).

A regulator / SOC analyst runs this to prove the ``audit_log`` has not been
tampered with. It performs two independent checks:

1. **Per-row integrity** — recompute each row's ``event_hash`` from its stored
   columns (``canonical_event_digest``) and compare. Detects content edits that
   left a stale hash.
2. **Daily Merkle roots** — group rows by UTC day (ordered by id), build the
   RFC 6962 Merkle root over the ``event_hash`` leaves, chain each day's root to
   the previous day, and compare against the signed roots published nightly.
   Detects deletion, insertion, reordering, and any hash change.

Exit code is non-zero on any divergence. The pure functions below carry the
logic and are unit-tested without a database.
"""

import argparse
import json
import os
import sys
from collections import OrderedDict
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from audit_merkle import (  # noqa: E402
    canonical_event_digest,
    canonical_timestamp,
    chained_daily_root,
    merkle_root,
)

# --------------------------------------------------------------------------- #
# Pure verification core (no DB, unit-tested)
# --------------------------------------------------------------------------- #


def recompute_row_digest(row: Dict[str, Any]) -> str:
    """Recompute a row's canonical event digest from its stored columns."""
    return canonical_event_digest(
        tenant_id=row.get("tenant_id"),
        category=row.get("category"),
        action=row.get("action"),
        resource_id=row.get("resource_id"),
        user_id=row.get("user_id"),
        timestamp=row.get("timestamp"),
        details=row.get("details"),
    )


def find_row_tampers(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rows whose stored ``event_hash`` does not match the recomputed digest."""
    tampers = []
    for row in rows:
        recomputed = recompute_row_digest(row)
        if recomputed != row.get("event_hash"):
            tampers.append(
                {
                    "id": row.get("id"),
                    "stored": row.get("event_hash"),
                    "recomputed": recomputed,
                }
            )
    return tampers


def compute_daily_roots(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group rows by UTC date (ordered by id) and compute each day's Merkle root."""
    by_date: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    for row in sorted(rows, key=lambda r: r["id"]):
        date = (canonical_timestamp(row["timestamp"]) or "")[:10]
        by_date.setdefault(date, []).append(row)

    out = []
    for date in sorted(by_date):
        day_rows = by_date[date]
        leaves = [bytes.fromhex(r["event_hash"]) for r in day_rows]
        out.append(
            {
                "date": date,
                "merkle_root": merkle_root(leaves).hex(),
                "count": len(day_rows),
                "first_id": day_rows[0]["id"],
                "last_id": day_rows[-1]["id"],
            }
        )
    return out


def chain_roots(daily: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Chain each day's Merkle root to the previous day's chained root."""
    out = []
    prev: Optional[bytes] = None
    for day in sorted(daily, key=lambda d: d["date"]):
        merkle_day = bytes.fromhex(day["merkle_root"])
        root = chained_daily_root(merkle_day, prev)
        entry = dict(day)
        entry["prev_root"] = prev.hex() if prev else None
        entry["root"] = root.hex()
        out.append(entry)
        prev = root
    return out


def diff_published(
    computed: List[Dict[str, Any]], published: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Divergences between computed chained roots and the published signed roots."""
    pub = {p["date"]: p["root"] for p in published}
    divergences = []
    for entry in computed:
        date = entry["date"]
        if date not in pub:
            divergences.append({"date": date, "reason": "missing_published_root"})
        elif pub[date] != entry["root"]:
            divergences.append(
                {
                    "date": date,
                    "reason": "root_mismatch",
                    "computed": entry["root"],
                    "published": pub[date],
                }
            )
    return divergences


# --------------------------------------------------------------------------- #
# Cosign signature gating (pure core, unit-tested)
# --------------------------------------------------------------------------- #


def signature_failures(sig_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Published roots whose detached cosign signature did not verify."""
    return [
        {"date": r["date"], "reason": r["reason"]}
        for r in sig_results
        if not r["valid"]
    ]


def trusted_published(
    published: List[Dict[str, Any]], sig_results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Keep only published roots whose cosign signature verified.

    A forged root with a bad/absent signature must never anchor the chain
    comparison — otherwise an attacker who can write both the DB and the
    published-roots directory could hide a tamper.
    """
    valid = {r["date"] for r in sig_results if r["valid"]}
    return [p for p in published if p["date"] in valid]


# --------------------------------------------------------------------------- #
# I/O wrappers (DB + published roots) — thin, exercised in integration
# --------------------------------------------------------------------------- #


def cosign_verify_blob(
    blob_path: str,
    sig_path: str,
    cert_path: str,
    *,
    cert_identity_regexp: str,
    cert_oidc_issuer: str,
) -> bool:  # pragma: no cover
    """Verify a keyless (Fulcio/OIDC) cosign detached signature over ``blob_path``.

    Returns True on a good signature, False if cosign rejects it. Raising would
    abort the whole run; instead a bad day is reported as a signature failure.
    """
    import subprocess

    try:
        subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--signature",
                sig_path,
                "--certificate",
                cert_path,
                "--certificate-identity-regexp",
                cert_identity_regexp,
                "--certificate-oidc-issuer",
                cert_oidc_issuer,
                blob_path,
            ],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def verify_published_signatures(published_dir: str, verify_fn) -> List[Dict[str, Any]]:
    """Verify the cosign signature of every ``<date>.json`` root in a directory.

    ``verify_fn(blob, sig, cert) -> bool`` is injected so the pairing logic is
    testable without cosign installed. Each result is ``{date, valid, reason}``
    where ``reason`` is ``None`` / ``"signature_invalid"`` / ``"signature_missing"``.
    """
    results = []
    if not os.path.isdir(published_dir):
        return results
    for name in sorted(os.listdir(published_dir)):
        if not name.endswith(".json"):
            continue
        date = name[: -len(".json")]
        blob = os.path.join(published_dir, name)
        sig = blob + ".sig"
        cert = blob + ".pem"
        if not (os.path.exists(sig) and os.path.exists(cert)):
            results.append(
                {"date": date, "valid": False, "reason": "signature_missing"}
            )
            continue
        ok = bool(verify_fn(blob, sig, cert))
        results.append(
            {"date": date, "valid": ok, "reason": None if ok else "signature_invalid"}
        )
    return results


def fetch_rows(database_url: str) -> List[Dict[str, Any]]:  # pragma: no cover
    import psycopg2
    import psycopg2.extras

    conn = psycopg2.connect(database_url)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT id, tenant_id, category, action, resource_id, user_id,
                   timestamp, details, event_hash
            FROM audit_log
            ORDER BY id
            """
        )
        rows = []
        for raw in cur.fetchall():
            row = dict(raw)
            if isinstance(row.get("details"), str):
                try:
                    row["details"] = json.loads(row["details"])
                except (ValueError, TypeError):
                    row["details"] = {}
            rows.append(row)
        return rows
    finally:
        conn.close()


def load_published_roots(
    published_dir: str,
) -> List[Dict[str, Any]]:  # pragma: no cover
    published = []
    if not os.path.isdir(published_dir):
        return published
    for name in sorted(os.listdir(published_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(published_dir, name)) as fh:
            published.append(json.load(fh))
    return published


def main(argv: Optional[List[str]] = None) -> int:  # pragma: no cover
    parser = argparse.ArgumentParser(description="Verify the SENTINEL audit ledger.")
    parser.add_argument(
        "--database-url",
        default=os.environ.get("AUDIT_DATABASE_URL") or os.environ.get("DATABASE_URL"),
    )
    parser.add_argument(
        "--published-dir",
        default=os.environ.get("AUDIT_ROOTS_DIR", "audit-roots"),
        help="Directory of nightly published signed root JSON files.",
    )
    parser.add_argument(
        "--cert-identity-regexp",
        default=os.environ.get("AUDIT_COSIGN_IDENTITY_REGEXP"),
        help="cosign keyless certificate identity regexp (the signing workflow "
        "SAN). Required to cryptographically trust published roots.",
    )
    parser.add_argument(
        "--cert-oidc-issuer",
        default=os.environ.get(
            "AUDIT_COSIGN_OIDC_ISSUER", "https://token.actions.githubusercontent.com"
        ),
        help="cosign keyless certificate OIDC issuer.",
    )
    args = parser.parse_args(argv)

    if not args.database_url:
        print("ERROR: --database-url or DATABASE_URL required", file=sys.stderr)
        return 2

    rows = fetch_rows(args.database_url)
    tampers = find_row_tampers(rows)
    computed = chain_roots(compute_daily_roots(rows))
    published = load_published_roots(args.published_dir)

    # Cryptographically gate which published roots may anchor the chain.
    sig_fails: List[Dict[str, Any]] = []
    if published and args.cert_identity_regexp:

        def _verify(blob, sig, cert):
            return cosign_verify_blob(
                blob,
                sig,
                cert,
                cert_identity_regexp=args.cert_identity_regexp,
                cert_oidc_issuer=args.cert_oidc_issuer,
            )

        sig_results = verify_published_signatures(args.published_dir, _verify)
        sig_fails = signature_failures(sig_results)
        trusted = trusted_published(published, sig_results)
    else:
        if published:
            print(
                "WARNING: cosign signature verification skipped "
                "(--cert-identity-regexp not set); published roots are NOT "
                "cryptographically trusted — integrity only.",
                file=sys.stderr,
            )
        trusted = published

    divergences = diff_published(computed, trusted) if trusted else []

    if tampers:
        first = tampers[0]
        print(
            f"TAMPER: row id={first['id']} stored={first['stored'][:16]}… "
            f"recomputed={first['recomputed'][:16]}…  ({len(tampers)} total)",
            file=sys.stderr,
        )
    if sig_fails:
        first = sig_fails[0]
        print(
            f"SIGNATURE FAILURE: {first['date']} {first['reason']} "
            f"({len(sig_fails)} total)",
            file=sys.stderr,
        )
    if divergences:
        first = divergences[0]
        print(
            f"ROOT DIVERGENCE: {first['date']} {first['reason']} "
            f"({len(divergences)} total)",
            file=sys.stderr,
        )

    if tampers or sig_fails or divergences:
        return 1

    print(
        f"OK: {len(rows)} rows, {len(computed)} daily roots verified"
        + (
            f" against {len(trusted)} cosign-verified published roots"
            if trusted
            else " (no trusted published roots — per-row integrity only)"
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
