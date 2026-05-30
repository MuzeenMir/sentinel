"""Persistence for reversible firewall enforcement actions.

The policy engine remains Redis-backed. This module stores only the durable
rollback contract for vendor enforcement side effects.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Callable

import psycopg2
import psycopg2.extras


ConnectFn = Callable[[], Any]


def _connect_pg():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is required for enforcement action storage")
    return psycopg2.connect(url)


class EnforcementActionStore:
    """PostgreSQL store for enforcement rollback records."""

    def __init__(self, connect: ConnectFn | None = None):
        self._connect = connect or _connect_pg

    @classmethod
    def from_env(cls) -> "EnforcementActionStore":
        return cls()

    def create_active_record(
        self,
        *,
        policy_id: str,
        vendor_name: str,
        rules: list[dict[str, Any]],
        apply_result: dict[str, Any],
        expires_at: datetime,
        tenant_id: int | None,
    ) -> dict[str, Any]:
        action_id = f"enf_{uuid.uuid4().hex[:24]}"
        conn = self._connect()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if tenant_id is not None:
                cur.execute(
                    "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
                    {"tenant_id": str(tenant_id)},
                )
            cur.execute(
                """
                INSERT INTO enforcement_actions (
                    tenant_id, action_id, policy_id, vendor_name, rules,
                    apply_result, expires_at, rollback_state,
                    confirmed_permanent
                )
                VALUES (
                    %(tenant_id)s, %(action_id)s, %(policy_id)s,
                    %(vendor_name)s, %(rules)s::jsonb,
                    %(apply_result)s::jsonb, %(expires_at)s,
                    'active', false
                )
                RETURNING
                    action_id, tenant_id, policy_id, vendor_name, rules,
                    apply_result, expires_at, rollback_state,
                    confirmed_permanent
                """,
                {
                    "tenant_id": tenant_id,
                    "action_id": action_id,
                    "policy_id": policy_id,
                    "vendor_name": vendor_name,
                    "rules": json.dumps(rules, default=str),
                    "apply_result": json.dumps(apply_result, default=str),
                    "expires_at": expires_at,
                },
            )
            row = cur.fetchone()
            conn.commit()
            return dict(row)
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def confirm_permanent(
        self,
        action_id: str,
        *,
        tenant_id: int | None,
    ) -> dict[str, Any] | None:
        conn = self._connect()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            if tenant_id is not None:
                cur.execute(
                    "SELECT set_config('app.tenant_id', %(tenant_id)s, true)",
                    {"tenant_id": str(tenant_id)},
                )
            cur.execute(
                """
                UPDATE enforcement_actions
                SET confirmed_permanent = true,
                    expires_at = NULL,
                    rollback_state = 'confirmed',
                    updated_at = NOW()
                WHERE action_id = %(action_id)s
                RETURNING
                    action_id, tenant_id, policy_id, vendor_name, rules,
                    expires_at, confirmed_permanent, rollback_state
                """,
                {"action_id": action_id},
            )
            row = cur.fetchone()
            conn.commit()
            return dict(row) if row else None
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def claim_expired_actions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        conn = self._connect()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(
                """
                WITH claimed AS (
                    SELECT id
                    FROM enforcement_actions
                    WHERE confirmed_permanent = false
                      AND expires_at IS NOT NULL
                      AND expires_at < NOW()
                      AND (
                          rollback_state = 'active'
                          OR (
                              rollback_state = 'revert_failed'
                              AND next_retry_at IS NOT NULL
                              AND next_retry_at <= NOW()
                          )
                      )
                    ORDER BY expires_at ASC
                    LIMIT %(limit)s
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE enforcement_actions AS ea
                SET rollback_state = 'pending',
                    updated_at = NOW()
                FROM claimed
                WHERE ea.id = claimed.id
                RETURNING
                    ea.action_id, ea.tenant_id, ea.policy_id,
                    ea.vendor_name, ea.rules, ea.expires_at,
                    ea.retry_count
                """,
                {"limit": limit},
            )
            rows = cur.fetchall()
            conn.commit()
            return [dict(row) for row in rows]
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def mark_reverted(self, action_id: str, *, reason: str) -> None:
        self._update_state(
            action_id,
            """
            UPDATE enforcement_actions
            SET rollback_state = 'reverted',
                reverted_at = NOW(),
                revert_reason = %(reason)s,
                updated_at = NOW()
            WHERE action_id = %(action_id)s
            """,
            {"action_id": action_id, "reason": reason},
        )

    def mark_revert_failed(self, action_id: str, *, reason: str) -> None:
        self._update_state(
            action_id,
            """
            UPDATE enforcement_actions
            SET rollback_state = 'revert_failed',
                revert_reason = %(reason)s,
                retry_count = retry_count + 1,
                next_retry_at = NOW()
                    + make_interval(secs => LEAST(3600, (POWER(2, retry_count)::int * 60))),
                updated_at = NOW()
            WHERE action_id = %(action_id)s
            """,
            {"action_id": action_id, "reason": reason},
        )

    def _update_state(
        self,
        action_id: str,
        sql: str,
        params: dict[str, Any],
    ) -> None:
        conn = self._connect()
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
