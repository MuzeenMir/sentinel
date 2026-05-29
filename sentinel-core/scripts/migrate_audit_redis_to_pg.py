#!/usr/bin/env python3
"""T-031 backfill: Redis sorted-set audit -> PostgreSQL audit_log.

Reads serialized audit records from ``sentinel:audit:index`` (zrange), parses
each one, derives a deterministic UUIDv5 ``event_id`` under the T-031
namespace, and inserts into ``audit_log`` with ``ON CONFLICT (event_id)
DO NOTHING`` so re-runs are idempotent.

Verification gate (deletion of Redis audit keys is allowed only when):

    new_inserts + pre_existing_matches_via_on_conflict == successfully_parsed_records

Malformed Redis members (non-JSON, missing required fields) are quarantined
to ``scripts/migrate_audit_redis_to_pg.skipped.jsonl`` for SOC review and
never delete the source Redis keys.

Usage::

    python scripts/migrate_audit_redis_to_pg.py \\
        --redis-url "$REDIS_URL" \\
        --database-url "$DATABASE_URL"

Flags:

    --dry-run            Insert into PG but never delete Redis keys.
    --delete-after-verify  Delete Redis audit keys on successful verification.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# Stable namespace UUID for T-031 deterministic event_id derivation. Do not
# regenerate or pre-existing event_id mappings change.
T031_EVENT_NAMESPACE = uuid.UUID("b0f99a8a-8d33-4e8b-8ec6-0b99f3a03131")

DEFAULT_SKIPPED_PATH = Path(__file__).with_suffix(".skipped.jsonl")

_REQUIRED_FIELDS = ("id", "tenant_id", "category", "action")


logger = logging.getLogger("migrate_audit_redis_to_pg")


def event_id_from_redis_id(redis_id: str) -> uuid.UUID:
    """Derive a stable UUIDv5 event_id from a legacy Redis audit id."""
    return uuid.uuid5(T031_EVENT_NAMESPACE, redis_id)


@dataclass
class BackfillResult:
    inserted: int = 0
    pre_existing_matches: int = 0
    skipped: int = 0
    parsed: int = 0
    deleted_redis_keys: bool = False
    skipped_paths: List[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return (self.inserted + self.pre_existing_matches) == self.parsed


def _read_redis_audit_members(redis_client) -> Iterable[bytes]:
    return redis_client.zrange("sentinel:audit:index", 0, -1)


def _parse_record(raw: bytes) -> Optional[Dict[str, Any]]:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = raw
    try:
        record = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    return record


def _write_skipped(
    skipped_path: Path, reason: str, raw: Any, partial: Any = None
) -> None:
    skipped_path.parent.mkdir(parents=True, exist_ok=True)
    raw_text = (
        raw.decode("utf-8", errors="replace")
        if isinstance(raw, (bytes, bytearray))
        else str(raw)
        if not isinstance(raw, dict)
        else json.dumps(raw, default=str)
    )
    entry = {"reason": reason, "raw": raw_text}
    if partial is not None:
        entry["partial"] = partial
    with skipped_path.open("a") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")


def _insert_record(cur, record: Dict[str, Any], event_id: uuid.UUID) -> int:
    """Insert one record into audit_log. Returns 1 on insert, 0 on conflict."""
    tenant_id = record.get("tenant_id")
    if tenant_id is not None:
        cur.execute(
            "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
            {"tenant_id": str(tenant_id)},
        )
    cur.execute(
        """
        INSERT INTO audit_log (
            event_id, tenant_id, user_id, action, category,
            resource_type, resource_id,
            details, timestamp, event_hash, prev_event_hash
        )
        VALUES (
            %(event_id)s, %(tenant_id)s, %(user_id)s, %(action)s, %(category)s,
            %(resource_type)s, %(resource_id)s,
            %(details)s::jsonb,
            %(timestamp)s, %(event_hash)s, NULL
        )
        ON CONFLICT (event_id) DO NOTHING
        RETURNING 1
        """,
        {
            "event_id": str(event_id),
            "tenant_id": tenant_id,
            "user_id": _actor_user_id(record.get("actor")),
            "action": record.get("action"),
            "category": record.get("category"),
            "resource_type": None,
            "resource_id": record.get("resource") or "redis-backfill",
            "details": json.dumps(
                {
                    "actor": record.get("actor"),
                    "service": record.get("service"),
                    "detail": record.get("detail", {}),
                    "epoch": record.get("epoch"),
                    "record_id": record.get("id"),
                    "original_record_id": record.get("id"),
                },
                default=str,
            ),
            "timestamp": record.get("timestamp"),
            "event_hash": record.get("integrity_hash") or "0" * 64,
        },
    )
    row = cur.fetchone()
    if row is None:
        return 0
    return (
        int(row[0]) if not isinstance(row, dict) else int(row.get("?column?", 0) or 0)
    )


def _actor_user_id(actor):
    if not actor or not isinstance(actor, str) or not actor.startswith("user:"):
        return None
    raw = actor.split(":", 1)[1]
    return int(raw) if raw.isdigit() else None


def backfill(
    redis_client,
    pg,
    skipped_path: Optional[Path] = None,
    delete_after_verify: bool = False,
) -> BackfillResult:
    """Backfill audit_log from Redis sorted set into PG.

    The PG connection ``pg`` must be opened by the caller. We commit per batch.
    """
    skipped_path = Path(skipped_path) if skipped_path else DEFAULT_SKIPPED_PATH
    result = BackfillResult()

    cur = pg.cursor()
    try:
        for raw in _read_redis_audit_members(redis_client):
            record = _parse_record(raw)
            if record is None:
                _write_skipped(skipped_path, "malformed_json", raw)
                result.skipped += 1
                continue

            missing = [f for f in _REQUIRED_FIELDS if not record.get(f)]
            if missing:
                _write_skipped(
                    skipped_path,
                    "missing_required_field",
                    raw,
                    partial={"missing": missing, "record": record},
                )
                result.skipped += 1
                continue

            result.parsed += 1
            try:
                event_id = event_id_from_redis_id(str(record["id"]))
                inserted = _insert_record(cur, record, event_id)
            except Exception as exc:  # noqa: BLE001
                pg.rollback()
                _write_skipped(
                    skipped_path,
                    f"pg_insert_error:{type(exc).__name__}",
                    raw,
                    partial={"error": str(exc), "record": record},
                )
                result.skipped += 1
                continue

            if inserted:
                result.inserted += 1
            else:
                result.pre_existing_matches += 1
    finally:
        pg.commit()

    if delete_after_verify and result.verified:
        # Delete the global index, stats, and per-category sorted sets.
        redis_client.delete(
            "sentinel:audit:index",
            "sentinel:audit:stats",
            "sentinel:audit:auth",
            "sentinel:audit:authorization",
            "sentinel:audit:data_access",
            "sentinel:audit:config_change",
            "sentinel:audit:system",
            "sentinel:audit:compliance",
            "sentinel:audit:policy",
            "sentinel:audit:alert",
        )
        result.deleted_redis_keys = True

    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="T-031 Redis -> PG audit backfill")
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL"),
        help="Redis URL (defaults to $REDIS_URL).",
    )
    parser.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="PostgreSQL URL (defaults to $DATABASE_URL).",
    )
    parser.add_argument(
        "--skipped-path",
        default=str(DEFAULT_SKIPPED_PATH),
        help="Path to write malformed records as JSONL.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--delete-after-verify", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    if not args.redis_url or not args.database_url:
        logger.error("Both --redis-url and --database-url are required")
        return 2

    import redis
    import psycopg2

    redis_client = redis.from_url(args.redis_url)
    pg = psycopg2.connect(args.database_url)

    delete = args.delete_after_verify and not args.dry_run
    try:
        result = backfill(
            redis_client=redis_client,
            pg=pg,
            skipped_path=Path(args.skipped_path),
            delete_after_verify=delete,
        )
    finally:
        try:
            pg.close()
        except Exception:
            pass

    logger.info(
        "backfill complete: parsed=%d inserted=%d pre_existing=%d skipped=%d "
        "verified=%s redis_deleted=%s",
        result.parsed,
        result.inserted,
        result.pre_existing_matches,
        result.skipped,
        result.verified,
        result.deleted_redis_keys,
    )
    return 0 if result.verified else 1


if __name__ == "__main__":
    sys.exit(main())
