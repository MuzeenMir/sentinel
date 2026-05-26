# T-031 Audit Log PG-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the shared production `audit_logger.audit_log()` path from Redis sorted sets to PostgreSQL `audit_log`, with PG-only writes, reads, stats, and Redis backfill.

**Architecture:** T-031 lands as one atomic PR stacked on `feat/phase-1-runtime-sentinel-app-role` until PR #41 merges. The PR first extends `audit_log` schema for event identity/category/hash-chain readiness, then flips `audit_logger.py` to a psycopg2-backed PG adapter, updates call sites according to the fail-closed/fail-soft policy, and ships an idempotent Redis backfill script plus operator docs. Redis remains in the product for non-audit runtime uses, but not for the shared audit logger.

**Tech Stack:** Python 3.12-compatible code, Flask services, psycopg2, Alembic, PostgreSQL RLS with `sentinel_app`, Redis only for one-time migration input, pytest, shell integration checks.

---

## Pre-Implementation Facts

- Worktree: `/mnt/c/Projects/Sentinel/dragon-scale/.worktrees/feat-phase-1-audit-log-redis-to-pg`
- Branch: `feat/phase-1-audit-log-redis-to-pg`
- Base while PR #41 is open: `feat/phase-1-runtime-sentinel-app-role`
- Rebase target after PR #41 merges: `main`
- Policy-orchestrator currently calls `vendor.apply_rules()` before `audit_log()`. T-031 must reorder to audit before policy persistence and vendor side effects.
- `policy_engine.create_policy()` persists to Redis immediately. The policy route must audit before calling it. If later implementation discovers hidden side effects before audit, stop and surface.
- `audit_log.id BIGINT PRIMARY KEY` currently has no default in `20260417_001_consolidate_schema.py`. The migration must verify the live table and add an owned sequence default unless the live DB already has identity/serial.

## File Structure

- Create: `sentinel-core/backend/migrations/versions/20260526_001_audit_log_pg_columns.py`
  - New Alembic revision after `20260524_001_app_login`.
  - Adds `event_id`, `category`, `event_hash`, `prev_event_hash`, audit indexes, column comments, and `id` sequence default when absent.
- Modify: `sentinel-core/backend/audit_logger.py`
  - Replaces Redis persistence with PG insert/read/stats helpers.
  - Keeps `verify_integrity()` and `_compute_integrity_hash()`.
  - Adds structured failure logging and `AuditLogError`.
- Modify: `sentinel-core/backend/auth-service/app.py`
  - Removes `redis_client=` audit arguments.
  - Applies fail-closed/fail-soft call-site policy.
  - Uses audit-before-token issuance for login success.
- Modify: `sentinel-core/backend/policy-orchestrator/app.py`
  - Removes `redis_client=` audit argument.
  - Reorders audit before policy persistence and vendor apply.
- Modify: `sentinel-core/backend/policy-orchestrator/requirements.txt`
  - Adds `psycopg2-binary>=2.9.9`.
- Modify: `sentinel-core/backend/api-gateway/app.py`
  - Calls PG-backed `query_audit_log()` and `get_audit_stats()` with no Redis audit dependency.
- Create: `sentinel-core/scripts/migrate_audit_redis_to_pg.py`
  - Idempotent Redis sorted-set backfill into PG using deterministic UUIDv5 event ids.
  - Writes malformed records to `sentinel-core/scripts/migrate_audit_redis_to_pg.skipped.jsonl`.
- Modify: `sentinel-core/scripts/runtime_role_isolation_check.sh`
  - Extends runtime role assertions for event insert, cross-tenant audit read isolation, and mutation denial.
- Modify: `sentinel-core/backend/tests/test_audit_logger.py`
  - Replaces Redis unit expectations with PG adapter expectations using mocked psycopg2 connections.
- Modify: `sentinel-core/backend/tests/test_auth_security.py`
  - Adds fail-closed admin role/status update test.
- Modify: `sentinel-core/backend/tests/test_policy_orchestrator.py`
  - Adds audit-before-vendor-apply ordering test.
- Create: `sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py`
  - Tests backfill idempotency, delete-after-verify, and skipped JSONL quarantine.
- Modify: `sentinel-core/readme.md`
  - Adds operator note with exact backfill command.
- Create: `.team/tickets/T-032-xai-audit-trail-consolidation-review.md`
  - Phase 2 follow-up for Redis-backed XAI `AuditTrail`.
- Do not modify: `/mnt/c/Projects/Sentinel/TASKS.md`
  - The parent meta-folder is not the git repository. Record the new T-032 path in the PR body instead.

---

### Task 1: Baseline And Live Schema Check

**Files:**
- Read: `sentinel-core/backend/migrations/versions/20260417_001_consolidate_schema.py`
- Read: `sentinel-core/scripts/fresh_db_check.sh`
- Read: `sentinel-core/scripts/runtime_role_isolation_check.sh`
- Read: `sentinel-core/backend/auth-service/app.py`
- Read: `sentinel-core/backend/policy-orchestrator/app.py`
- Read: `sentinel-core/backend/api-gateway/app.py`

- [ ] **Step 1: Confirm branch and stack**

Run:

```bash
git status --short --branch
git log --oneline --decorate --max-count=6
```

Expected: branch is `feat/phase-1-audit-log-redis-to-pg`, clean worktree, and commits include `feat/phase-1-runtime-sentinel-app-role` below the T-031 spec commits.

- [ ] **Step 2: Run targeted baseline tests**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_audit_logger.py -q
python -m pytest sentinel-core/backend/tests/test_auth_security.py -q
python -m pytest sentinel-core/backend/tests/test_policy_orchestrator.py -q
```

Expected: tests pass or fail only for already-known environment dependency reasons. If failures are unrelated to T-031, capture them in the PR body before implementing.

- [ ] **Step 3: Verify live `audit_log.id` default state**

Run a throwaway migrated DB and inspect `audit_log.id`:

```bash
cd sentinel-core
bash scripts/fresh_db_check.sh
```

Then, against the fresh check DB while it is still available, or by running an equivalent local Postgres container, execute:

```sql
SELECT
  a.attidentity,
  pg_get_expr(d.adbin, d.adrelid) AS default_expr
FROM pg_attribute a
LEFT JOIN pg_attrdef d
  ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = 'audit_log'::regclass
  AND a.attname = 'id';
```

Expected today: `attidentity = ''` and `default_expr IS NULL`. If the live DB already has identity or serial, keep the migration's guard but do not force a new sequence.

- [ ] **Step 4: Verify audit logger import path**

Run:

```bash
rg -n "from audit_logger import|import audit_logger" sentinel-core/backend/auth-service/app.py sentinel-core/backend/policy-orchestrator/app.py sentinel-core/backend/api-gateway/app.py
```

Expected: services import `audit_logger` as a top-level backend module. Confirm Dockerfiles or test setup put `sentinel-core/backend` on `PYTHONPATH` or copy `audit_logger.py` into the service image before implementation changes.

- [ ] **Step 5: Commit nothing**

No code changes in this task. Record the schema check result in the PR body draft.

---

### Task 2: Alembic Schema Migration

**Files:**
- Create: `sentinel-core/backend/migrations/versions/20260526_001_audit_log_pg_columns.py`
- Test: `sentinel-core/scripts/fresh_db_check.sh`
- Test: `sentinel-core/scripts/runtime_role_isolation_check.sh`

- [ ] **Step 1: Write the failing migration assertion**

Extend `sentinel-core/scripts/runtime_role_isolation_check.sh` after `alembic upgrade head` with a temporary assertion that will fail before the migration exists:

```bash
echo "==> [schema] audit_log has T-031 PG-only audit columns"
SCHEMA_COLUMNS=$(psql_as_owner -t -A -c "
  SELECT string_agg(column_name, ',' ORDER BY column_name)
  FROM information_schema.columns
  WHERE table_name = 'audit_log'
    AND column_name IN ('event_id', 'category', 'event_hash', 'prev_event_hash')
")
if [ "${SCHEMA_COLUMNS}" != "category,event_hash,event_id,prev_event_hash" ]; then
  echo "FAIL: audit_log T-031 columns missing: ${SCHEMA_COLUMNS}" >&2
  exit 1
fi
```

- [ ] **Step 2: Run the check to verify RED**

Run:

```bash
cd sentinel-core
bash scripts/runtime_role_isolation_check.sh
```

Expected: FAIL with `audit_log T-031 columns missing`.

- [ ] **Step 3: Create migration with guarded DDL**

Create `sentinel-core/backend/migrations/versions/20260526_001_audit_log_pg_columns.py`:

```python
"""Add PG-only audit event columns for T-031.

Revision ID: 20260526_001_audit_pg
Revises: 20260524_001_app_login
Create Date: 2026-05-26
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision: str = "20260526_001_audit_pg"
down_revision: Union[str, None] = "20260524_001_app_login"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_column(bind, "audit_log", "event_id"):
        op.add_column(
            "audit_log",
            sa.Column(
                "event_id",
                postgresql.UUID(as_uuid=False),
                nullable=False,
                server_default=sa.text("gen_random_uuid()"),
            ),
        )

    if not _has_column(bind, "audit_log", "category"):
        op.add_column("audit_log", sa.Column("category", sa.String(50), nullable=True))
        op.execute("""
            UPDATE audit_log
            SET category = COALESCE(NULLIF(resource_type, ''), 'system')
            WHERE category IS NULL
        """)
        op.alter_column("audit_log", "category", nullable=False)

    if not _has_column(bind, "audit_log", "event_hash"):
        op.add_column("audit_log", sa.Column("event_hash", sa.Text(), nullable=True))
        op.execute("""
            UPDATE audit_log
            SET event_hash = encode(
                digest(
                    concat_ws('|',
                        COALESCE(tenant_id::text, ''),
                        COALESCE(action, ''),
                        COALESCE(resource_type, ''),
                        COALESCE(resource_id, ''),
                        COALESCE(details::text, ''),
                        COALESCE(timestamp::text, '')
                    ),
                    'sha256'
                ),
                'hex'
            )
            WHERE event_hash IS NULL
        """)
        op.alter_column("audit_log", "event_hash", nullable=False)

    if not _has_column(bind, "audit_log", "prev_event_hash"):
        op.add_column("audit_log", sa.Column("prev_event_hash", sa.Text(), nullable=True))

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_attrdef d
                JOIN pg_attribute a
                  ON a.attrelid = d.adrelid AND a.attnum = d.adnum
                WHERE d.adrelid = 'audit_log'::regclass
                  AND a.attname = 'id'
            ) AND NOT EXISTS (
                SELECT 1
                FROM pg_attribute
                WHERE attrelid = 'audit_log'::regclass
                  AND attname = 'id'
                  AND attidentity <> ''
            ) THEN
                CREATE SEQUENCE IF NOT EXISTS audit_log_id_seq OWNED BY audit_log.id;
                ALTER TABLE audit_log
                    ALTER COLUMN id SET DEFAULT nextval('audit_log_id_seq');
                PERFORM setval(
                    'audit_log_id_seq',
                    COALESCE((SELECT MAX(id) FROM audit_log), 0) + 1,
                    false
                );
            END IF;
        END $$;
    """)

    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_log_event_id ON audit_log (event_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp_desc "
        "ON audit_log (tenant_id, timestamp DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_category_timestamp_desc "
        "ON audit_log (tenant_id, category, timestamp DESC)"
    )
    op.execute("""
        COMMENT ON COLUMN audit_log.prev_event_hash IS
        'NULL means this audit row is not yet part of the cryptographic chain; consumers must treat NULL as chain verification not applicable, not as tampering.'
    """)
    op.execute("""
        COMMENT ON COLUMN audit_log.event_hash IS
        'sha256 of canonical event payload. Rows with timestamps before T-031 migration carry a backfill placeholder hash, not a tamper-detection hash; the cryptographic chain begins at the first post-migration row.'
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_audit_tenant_category_timestamp_desc")
    op.execute("DROP INDEX IF EXISTS idx_audit_tenant_timestamp_desc")
    op.execute("DROP INDEX IF EXISTS uq_audit_log_event_id")
    for column in ("prev_event_hash", "event_hash", "category", "event_id"):
        op.drop_column("audit_log", column)
```

- [ ] **Step 4: Run migration checks to verify GREEN**

Run:

```bash
cd sentinel-core
bash scripts/fresh_db_check.sh
bash scripts/runtime_role_isolation_check.sh
```

Expected: both pass.

- [ ] **Step 5: Commit migration**

Run:

```bash
git add sentinel-core/backend/migrations/versions/20260526_001_audit_log_pg_columns.py sentinel-core/scripts/runtime_role_isolation_check.sh
git commit -m "feat(migrations): add PG audit event columns for T-031"
```

---

### Task 3: PG-Backed Audit Logger Unit Tests

**Files:**
- Modify: `sentinel-core/backend/tests/test_audit_logger.py`

- [ ] **Step 1: Replace Redis fake with PG fake**

Write tests that assert PG behavior before implementation. Add this fake connection near the top of `test_audit_logger.py`:

```python
class FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.statements = []
        self.params = []

    def execute(self, sql, params=None):
        self.statements.append(str(sql))
        self.params.append(params or {})

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True
```

- [ ] **Step 2: Add failing audit insert test**

Add:

```python
def test_audit_log_inserts_into_postgres_and_not_redis(monkeypatch):
    cursor = FakeCursor()
    conn = FakeConnection(cursor)
    redis_client = MagicMock()
    monkeypatch.setenv("DATABASE_URL", "postgresql://sentinel_app:test@db/sentinel")
    monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

    with patch("audit_logger._in_request_context", return_value=False):
        rid = audit_log(
            AuditCategory.AUTH,
            "login_success",
            actor="user:1",
            tenant_id=7,
            resource="auth-service",
            detail={"ip": "127.0.0.1"},
            redis_client=redis_client,
        )

    assert rid.startswith("audit_")
    assert any("INSERT INTO audit_log" in sql for sql in cursor.statements)
    assert any("set_config('app.tenant_id'" in sql for sql in cursor.statements)
    assert conn.committed is True
    redis_client.zadd.assert_not_called()
```

- [ ] **Step 3: Add failing query/stats/failure tests**

Add:

```python
def test_query_audit_log_reads_pg_and_filters_actor(monkeypatch):
    cursor = FakeCursor(
        rows=[
            {
                "event_id": "11111111-1111-1111-1111-111111111111",
                "timestamp": "2026-05-26T00:00:00Z",
                "category": "auth",
                "action": "login_success",
                "resource_id": "auth-service",
                "tenant_id": 1,
                "details": {"actor": "user:1", "service": "auth-service", "detail": {}},
                "event_hash": "a" * 64,
            }
        ]
    )
    monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

    results = query_audit_log(category="auth", actor="user:1", tenant_id=1)

    assert results[0]["category"] == "auth"
    assert results[0]["actor"] == "user:1"
    assert any("FROM audit_log" in sql for sql in cursor.statements)


def test_get_audit_stats_reads_pg(monkeypatch):
    cursor = FakeCursor(rows=[{"category": "auth", "count": 2}, {"category": "policy", "count": 1}])
    monkeypatch.setattr("audit_logger._connect_pg", lambda: FakeConnection(cursor))

    stats = get_audit_stats(tenant_id=1)

    assert stats["total_events"] == 3
    assert stats["by_category"] == {"auth": 2, "policy": 1}


def test_audit_insert_failure_logs_structured_payload_and_raises(monkeypatch):
    class BrokenCursor(FakeCursor):
        def execute(self, sql, params=None):
            raise RuntimeError("pg down")

    conn = FakeConnection(BrokenCursor())
    monkeypatch.setattr("audit_logger._connect_pg", lambda: conn)

    with patch("audit_logger.logger") as logger:
        with pytest.raises(Exception):
            audit_log(AuditCategory.AUTH, "login", actor="user:1", detail={"password": "secret"})

    assert conn.rolled_back is True
    logger.error.assert_called()
    _, kwargs = logger.error.call_args
    assert kwargs["extra"]["audit_failure"] is True
    assert "password" not in json.dumps(kwargs["extra"]["audit_event"])
```

- [ ] **Step 4: Run tests to verify RED**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_audit_logger.py -q
```

Expected: FAIL because `_connect_pg` and PG query functions are missing or still Redis-backed.

- [ ] **Step 5: Commit nothing**

Leave tests failing for Task 4.

---

### Task 4: Implement PG-Backed Audit Logger

**Files:**
- Modify: `sentinel-core/backend/audit_logger.py`
- Modify: `sentinel-core/backend/policy-orchestrator/requirements.txt`
- Modify: `sentinel-core/backend/requirements-test.txt` if psycopg2 is unavailable in the test venv

- [ ] **Step 1: Add PG connection and error types**

In `audit_logger.py`, add:

```python
import re
import psycopg2
import psycopg2.extras


class AuditLogError(RuntimeError):
    """Raised when the append-only PG audit sink cannot persist an event."""


_SENSITIVE_KEYS = re.compile(r"(password|token|secret|authorization|cookie|mfa|code)", re.I)
```

Add `psycopg2-binary>=2.9.9` to `sentinel-core/backend/policy-orchestrator/requirements.txt`. Add it to `sentinel-core/backend/requirements-test.txt` only if the focused tests cannot import psycopg2.

- [ ] **Step 2: Add helpers**

Add:

```python
def _connect_pg():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise AuditLogError("DATABASE_URL is required for PG audit logging")
    return psycopg2.connect(url)


def _sanitize_for_failure_log(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_KEYS.search(str(key)) else _sanitize_for_failure_log(val)
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_for_failure_log(item) for item in value]
    return value


def _actor_user_id(actor: Optional[str]) -> Optional[int]:
    if not actor or not actor.startswith("user:"):
        return None
    raw = actor.split(":", 1)[1]
    return int(raw) if raw.isdigit() else None
```

- [ ] **Step 3: Replace Redis write with PG insert**

`audit_log()` must:

1. Build the same compatibility record shape.
2. Compute `event_hash` with `_compute_integrity_hash(record)`.
3. Open PG connection.
4. Start transaction.
5. If tenant id is present, execute `SELECT set_config('app.tenant_id', %(tenant_id)s, true)`.
6. Insert into `audit_log`.
7. Commit and return the legacy `audit_...` string id for API compatibility.

Construct `details_payload` exactly as:

```python
details_payload = {
    "actor": actor,
    "service": _SERVICE_NAME,
    "detail": detail or {},
    "epoch": record["epoch"],
    "record_id": record_id,
}
```

Backfill adds `details_payload["original_record_id"] = redis_id`; normal new writes do not.

Use this SQL shape:

```python
cur.execute(
    """
    INSERT INTO audit_log (
        tenant_id, user_id, action, category, resource_type, resource_id,
        details, timestamp, event_hash, prev_event_hash
    )
    VALUES (
        %(tenant_id)s, %(user_id)s, %(action)s, %(category)s,
        %(resource_type)s, %(resource_id)s, %(details)s::jsonb,
        %(timestamp)s, %(event_hash)s, NULL
    )
    """,
    {
        "tenant_id": tenant_id,
        "user_id": _actor_user_id(actor),
        "action": action,
        "category": category_value,
        "resource_type": detail.get("resource_type") if isinstance(detail, dict) else None,
        "resource_id": resource or _SERVICE_NAME,
        "details": json.dumps(details_payload, default=str),
        "timestamp": record["timestamp"],
        "event_hash": record["integrity_hash"],
    },
)
```

On failure:

```python
logger.error(
    "audit_log_insert_failed",
    exc_info=True,
    extra={
        "audit_failure": True,
        "audit_event": _sanitize_for_failure_log(record),
    },
)
raise AuditLogError("failed to persist audit event") from exc
```

- [ ] **Step 4: Add module-level failure-mode note**

Update the `audit_logger.py` module docstring with:

```python
"""...
Failure-mode note: audit rows are committed in their own psycopg2 transaction,
separate from any caller's SQLAlchemy session. An audit row may exist for an
action whose subsequent durable commit failed. This is intentional: the
append-only audit ledger records intent. Callers MUST audit BEFORE committing
the act (audit-then-act ordering) so any persisted state change is preceded by
an audit row; the inverse is acceptable.
"""
```

- [ ] **Step 5: Replace query and stats**

`query_audit_log()` signature:

```python
def query_audit_log(
    category: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    tenant_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
```

Read from PG only. Actor filter intentionally uses `details->>'actor'` and is not indexed in T-031; add this code comment above the actor predicate:

```python
# Actor-only SOC lookups are intentionally not indexed in T-031. Add
# (tenant_id, actor, timestamp DESC) or an expression index on details->>'actor'
# only if SOC reports slow actor queries.
```

`get_audit_stats()` signature:

```python
def get_audit_stats(tenant_id: Optional[int] = None) -> Dict[str, Any]:
```

- [ ] **Step 6: Run tests to verify GREEN**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_audit_logger.py -q
python -m ruff check sentinel-core/backend/audit_logger.py sentinel-core/backend/tests/test_audit_logger.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add sentinel-core/backend/audit_logger.py sentinel-core/backend/policy-orchestrator/requirements.txt sentinel-core/backend/requirements-test.txt sentinel-core/backend/tests/test_audit_logger.py
git commit -m "feat(audit): write shared audit log to PostgreSQL"
```

---

### Task 5: Auth-Service Call-Site Failure Policy

**Files:**
- Modify: `sentinel-core/backend/auth-service/app.py`
- Modify: `sentinel-core/backend/tests/test_auth_security.py`

- [ ] **Step 1: Write failing admin update fail-closed test**

In `test_auth_security.py`, add a test that creates admin + target user, logs in as admin, patches `auth_mod.audit_log` to raise `AuditLogError`, calls `PUT /api/v1/auth/users/<id>`, and verifies the target row is unchanged:

```python
def test_admin_user_update_rolls_back_when_audit_insert_fails(client):
    _create_user(client, username="admin", role="admin")
    _create_user(client, username="target", role="viewer")
    token = _login(client, "admin").get_json()["access_token"]

    with app.app_context():
        target = User.query.filter_by(username="target").first()
        target_id = target.id

    with patch.object(auth_mod, "audit_log", side_effect=auth_mod.AuditLogError("pg down")):
        resp = client.put(
            f"/api/v1/auth/users/{target_id}",
            json={"role": "admin"},
            headers=_auth(token),
        )

    assert resp.status_code == 500
    with app.app_context():
        target = User.query.get(target_id)
        assert target.role == UserRole.VIEWER
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_auth_security.py::test_admin_user_update_rolls_back_when_audit_insert_fails -q
```

Expected: FAIL because the role update currently commits before audit failure.

- [ ] **Step 3: Import `AuditLogError` and remove Redis audit arguments**

Change import:

```python
from audit_logger import audit_log, AuditCategory, AuditLogError
```

Remove `redis_client=redis_client` from all `audit_log()` calls.

- [ ] **Step 4: Add soft-audit helper for deny/logout paths**

Add near route helpers:

```python
def _audit_fail_soft(*args, **kwargs) -> None:
    try:
        audit_log(*args, **kwargs)
    except AuditLogError:
        logger.exception("Audit log unavailable for fail-soft event")
```

Use `_audit_fail_soft()` for:

- `login_blocked_inactive`
- `login_blocked_locked`
- `login_failed`
- `logout`

- [ ] **Step 5: Apply audit-before-act ordering**

For `login_success`, audit before `reset_login_attempts(user)` and before token issuance:

```python
audit_log(
    AuditCategory.AUTH,
    "login_success",
    actor=f"user:{user.id}",
    tenant_id=user.tenant_id,
    detail={"username": user.username, "ip": ip_addr},
)
reset_login_attempts(user)
access_token = create_access_token(...)
```

For fail-closed committed mutations (`register`, `update_user`, `create_tenant`, `deactivate_tenant`), keep the DB transaction open until after audit succeeds:

```python
db.session.flush()
audit_log(...)
db.session.commit()
```

On `AuditLogError`, call `db.session.rollback()` and return 500.

Failure-mode note for reviewers: `audit_log()` commits in its own psycopg2 transaction. If `audit_log()` succeeds and the subsequent SQLAlchemy `db.session.commit()` fails, the audit row remains and records attempted intent. This is intentional. The forbidden inverse is a durable mutation with no preceding audit row.

- [ ] **Step 6: Run focused tests**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_auth_security.py -q
python -m pytest sentinel-core/backend/tests/test_auth_service.py -q
python -m ruff check sentinel-core/backend/auth-service/app.py sentinel-core/backend/tests/test_auth_security.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add sentinel-core/backend/auth-service/app.py sentinel-core/backend/tests/test_auth_security.py
git commit -m "fix(auth-service): enforce audit failure policy for auth mutations"
```

---

### Task 6: Policy-Orchestrator Audit-Before-Side-Effects

**Files:**
- Modify: `sentinel-core/backend/policy-orchestrator/app.py`
- Modify: `sentinel-core/backend/tests/test_policy_orchestrator.py`

- [ ] **Step 1: Write failing ordering test**

Add:

```python
def test_create_policy_audits_before_policy_persist_and_vendor_apply(client):
    calls = []

    def audit_side_effect(*_args, **_kwargs):
        calls.append("audit")

    def create_side_effect(*_args, **_kwargs):
        calls.append("create")
        return {"id": "pol_test", "name": "Block SSH", "rules": []}

    def apply_side_effect(*_args, **_kwargs):
        calls.append("apply")
        return {"success": True, "message": "applied"}

    orch_app.audit_log = MagicMock(side_effect=audit_side_effect)
    orch_app.policy_engine.create_policy = MagicMock(side_effect=create_side_effect)
    _mock_vendor.apply_rules.side_effect = apply_side_effect

    resp = client.post(
        "/api/v1/policies",
        json={"name": "Block SSH", "action": "DENY", "vendors": ["iptables"]},
    )

    assert resp.status_code == 201
    assert calls == ["audit", "create", "apply"]
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_policy_orchestrator.py::test_create_policy_audits_before_policy_persist_and_vendor_apply -q
```

Expected: FAIL because current order is create, apply, audit.

- [ ] **Step 3: Reorder route**

In `create_policy()`, after validation/conflict checks and before `policy_engine.create_policy()`, call:

```python
audit_log(
    AuditCategory.POLICY,
    "policy_created",
    detail={"name": data.get("name"), "action": data.get("action")},
)
```

Then create policy and apply vendors. If implementation discovers an irreversible side effect before this point, stop and ask Marcus/Mir.

- [ ] **Step 4: Run focused tests**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_policy_orchestrator.py -q
python -m ruff check sentinel-core/backend/policy-orchestrator/app.py sentinel-core/backend/tests/test_policy_orchestrator.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add sentinel-core/backend/policy-orchestrator/app.py sentinel-core/backend/tests/test_policy_orchestrator.py
git commit -m "fix(policy-orchestrator): audit policy create before side effects"
```

---

### Task 7: API Gateway Audit Reads

**Files:**
- Modify: `sentinel-core/backend/api-gateway/app.py`
- Modify: `sentinel-core/backend/tests/test_api_gateway.py`

- [ ] **Step 1: Write failing API read test**

Add or update an API Gateway test so `/api/v1/audit/events` calls `query_audit_log()` without passing Redis:

```python
def test_audit_events_queries_pg_audit_log(client, monkeypatch):
    captured = {}

    def fake_query(**kwargs):
        captured.update(kwargs)
        return [{"id": "audit_1", "category": "auth"}]

    monkeypatch.setattr(api_mod, "query_audit_log", fake_query)

    resp = client.get("/api/v1/audit/events?category=auth&limit=10")

    assert resp.status_code == 200
    assert captured["category"] == "auth"
    assert captured["limit"] == 10
```

- [ ] **Step 2: Run test to verify RED**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_api_gateway.py::test_audit_events_queries_pg_audit_log -q
```

Expected: FAIL if the route still passes `redis_client` positionally.

- [ ] **Step 3: Update routes**

Change:

```python
records = query_audit_log(
    category=category,
    start_time=start_time,
    end_time=end_time,
    actor=actor,
    limit=min(limit, 1000),
    offset=offset,
)
stats = get_audit_stats()
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_api_gateway.py -q
python -m ruff check sentinel-core/backend/api-gateway/app.py sentinel-core/backend/tests/test_api_gateway.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add sentinel-core/backend/api-gateway/app.py sentinel-core/backend/tests/test_api_gateway.py
git commit -m "fix(api-gateway): read audit events from PostgreSQL"
```

---

### Task 8: Redis Backfill Script

**Files:**
- Create: `sentinel-core/scripts/migrate_audit_redis_to_pg.py`
- Create: `sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py`

- [ ] **Step 1: Write failing backfill tests**

Create `test_migrate_audit_redis_to_pg.py` with tests for:

```python
def test_event_id_is_deterministic_from_redis_id():
    first = script.event_id_from_redis_id("audit_abc")
    second = script.event_id_from_redis_id("audit_abc")
    assert first == second


def test_backfill_idempotency_keeps_row_count_stable(fake_redis, fake_pg):
    fake_redis.add({"id": "audit_abc", "tenant_id": 1, "category": "auth", "action": "login", "actor": "user:1", "detail": {}})
    first = script.backfill(redis_client=fake_redis, pg=fake_pg, delete_after_verify=True)
    second = script.backfill(redis_client=fake_redis, pg=fake_pg, delete_after_verify=True)
    assert first.inserted == 1
    assert second.inserted == 0
    assert fake_pg.row_count == 1


def test_malformed_records_go_to_skipped_jsonl(tmp_path, fake_redis, fake_pg):
    fake_redis.add_raw("not-json")
    skipped = tmp_path / "skipped.jsonl"
    result = script.backfill(redis_client=fake_redis, pg=fake_pg, skipped_path=skipped)
    assert result.skipped == 1
    assert "malformed_json" in skipped.read_text()
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py -q
```

Expected: FAIL because script does not exist.

- [ ] **Step 3: Implement script**

Implement these functions:

```python
T031_EVENT_NAMESPACE = uuid.UUID("b0f99a8a-8d33-4e8b-8ec6-0b99f3a03131")
DEFAULT_SKIPPED_PATH = Path(__file__).with_suffix(".skipped.jsonl")


def event_id_from_redis_id(redis_id: str) -> uuid.UUID:
    return uuid.uuid5(T031_EVENT_NAMESPACE, redis_id)
```

Backfill behavior:

- Reads all members from `sentinel:audit:index`.
- Parses JSON.
- Requires `id`, `tenant_id`, `category`, `action`.
- Uses `INSERT ... ON CONFLICT (event_id) DO NOTHING`.
- Executes `SELECT set_config('app.tenant_id', %(tenant_id)s, true)` before insert.
- Writes skipped rows to `migrate_audit_redis_to_pg.skipped.jsonl` with `reason`, `raw`, and parsed partial fields when available.
- Deletes `sentinel:audit:index`, `sentinel:audit:stats`, and category keys only after verification passes and not in `--dry-run`.

Verification is defined as:

```text
new_inserts + pre_existing_matches_via_on_conflict == successfully_parsed_redis_audit_entries
```

On a second run, `new_inserts` may be zero, but `pre_existing_matches_via_on_conflict` must equal the successfully parsed Redis entries before deletion is allowed.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py -q
python -m ruff check sentinel-core/scripts/migrate_audit_redis_to_pg.py sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add sentinel-core/scripts/migrate_audit_redis_to_pg.py sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py
git commit -m "feat(audit): add Redis to PostgreSQL audit backfill"
```

---

### Task 9: Runtime Role Integration Check

**Files:**
- Modify: `sentinel-core/scripts/runtime_role_isolation_check.sh`

- [ ] **Step 1: Add failing assertions**

Extend the script after existing RLS assertions:

```bash
echo "==> [audit] sentinel_app can insert audit row with tenant context"
psql_as_app -v ON_ERROR_STOP=1 -1 -c "
  SELECT set_config('app.tenant_id', '1', true);
  INSERT INTO audit_log (tenant_id, action, category, resource_id, details, event_hash)
  VALUES (1, 'runtime_check', 'system', 'runtime-role-check', '{}'::jsonb, repeat('a', 64));
" >/dev/null

echo "==> [audit] tenant 2 cannot read tenant 1 audit row"
COUNT=$(psql_as_app -v ON_ERROR_STOP=1 -t -A -1 -c "
  SELECT set_config('app.tenant_id', '2', true);
  SELECT count(*) FROM audit_log WHERE action = 'runtime_check';
" | tail -1 | tr -d ' ')
if [ "${COUNT}" != "0" ]; then
  echo "FAIL: tenant 2 saw tenant 1 audit rows" >&2
  exit 1
fi
```

- [ ] **Step 2: Run to verify RED if migration/logger tasks are incomplete**

Run:

```bash
cd sentinel-core
bash scripts/runtime_role_isolation_check.sh
```

Expected after Tasks 2-4: PASS. If run before schema migration, it should fail on missing columns.

- [ ] **Step 3: Commit**

Run:

```bash
git add sentinel-core/scripts/runtime_role_isolation_check.sh
git commit -m "test(audit): verify runtime role audit log isolation"
```

---

### Task 10: Operator Docs, Release-Please Notes, And XAI Follow-Up

**Files:**
- Modify: `sentinel-core/readme.md`
- Create: `.team/tickets/T-032-xai-audit-trail-consolidation-review.md`

- [ ] **Step 1: Verify release-please changelog behavior**

Run:

```bash
sed -n '1,180p' release-please-config.json
sed -n '1,120p' .github/workflows/release-please.yml
```

Expected: release-please owns `CHANGELOG.md` from Conventional Commit metadata. Do not edit `CHANGELOG.md` directly for a pending v1.1.4 block; it may be regenerated or duplicated by the release bot.

- [ ] **Step 2: Add release-please BREAKING footer to the final implementation commit**

The final implementation commit or PR squash body must include:

```text
feat(audit): move shared audit log to PostgreSQL

BREAKING CHANGE: T-031 moves the shared SOC2 audit path from Redis sorted sets to PostgreSQL audit_log. Operators upgrading from a Redis-backed audit deployment must run `python scripts/migrate_audit_redis_to_pg.py --redis-url "$REDIS_URL" --database-url "$DATABASE_URL"` before promoting v1.1.4+. Malformed Redis records are quarantined in `scripts/migrate_audit_redis_to_pg.skipped.jsonl`.
```

Release-please should generate the v1.1.4 changelog entry from that footer.

- [ ] **Step 3: Add README operator note**

In `sentinel-core/readme.md`, add an "Audit log migration" note under Quick start or Operations:

````markdown
### Audit log migration for v1.1.4+

The shared SOC2 audit path uses PostgreSQL `audit_log` as the only audit storage
surface. Operators upgrading from a Redis-backed audit deployment must run the
one-shot backfill before promoting v1.1.4+:

```shell
python scripts/migrate_audit_redis_to_pg.py \
  --redis-url "$REDIS_URL" \
  --database-url "$DATABASE_URL"
```

Skipped malformed records are quarantined in
`scripts/migrate_audit_redis_to_pg.skipped.jsonl` for SOC review.
````

- [ ] **Step 4: File XAI follow-up ticket**

Create `.team/tickets/T-032-xai-audit-trail-consolidation-review.md`:

```markdown
# T-032 [ds] — review/migrate XAI AuditTrail under Phase 2 consolidation

Owner: Backlog
Reviewer: Marcus + Mir if it becomes an audit-schema change
Priority: P2
Filed: 2026-05-26
Phase: 2

## Context

T-031 retires Redis storage for the shared production `audit_logger.audit_log()`
path. `sentinel-core/backend/xai-service/reports/audit_trail.py` remains a
separate Redis-backed explanation trail for XAI records and is not covered by
the T-031 PG append-only claim.

## Acceptance

- Decide whether XAI explanation trails become PG-backed audit rows, separate
  XAI provenance records, or are removed during XAI consolidation.
- Remove or update Redis-backed `AuditTrail` claims so no product copy implies
  it is protected by the PG `audit_log` role-level REVOKE matrix.
- Add regression tests for the chosen storage path.
```

- [ ] **Step 5: Run docs checks**

Run:

```bash
git diff --check
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add sentinel-core/readme.md .team/tickets/T-032-xai-audit-trail-consolidation-review.md
git commit -m "docs(audit): add PG audit migration operator notes"
```

---

### Task 11: Full Verification And PR Prep

**Files:**
- No new files unless fixing verification failures.

- [ ] **Step 1: Run focused backend checks**

Run:

```bash
python -m pytest sentinel-core/backend/tests/test_audit_logger.py -q
python -m pytest sentinel-core/backend/tests/test_migrate_audit_redis_to_pg.py -q
python -m pytest sentinel-core/backend/tests/test_auth_security.py -q
python -m pytest sentinel-core/backend/tests/test_policy_orchestrator.py -q
python -m pytest sentinel-core/backend/tests/test_api_gateway.py -q
```

Expected: PASS.

- [ ] **Step 2: Run migration and runtime role checks**

Run:

```bash
cd sentinel-core
bash scripts/fresh_db_check.sh
bash scripts/runtime_role_isolation_check.sh
```

Expected: PASS.

CI note: `integration-migrations` is a required check since T-029 and will exercise the new migration against a fresh PostgreSQL container. If it fails in CI, fix it before requesting review.

- [ ] **Step 3: Run lint with CI ruff version**

Run:

```bash
uvx ruff@0.5.6 check sentinel-core/backend sentinel-core/scripts
uvx ruff@0.5.6 format --check sentinel-core/backend sentinel-core/scripts
```

Expected: PASS. Use `uvx ruff@0.5.6 format` on touched files only if formatting fails.

- [ ] **Step 4: Run final status**

Run:

```bash
git status --short --branch
git log --oneline --decorate --max-count=12
```

Expected: clean worktree.

- [ ] **Step 5: PR body notes**

Include these facts in the PR body:

- Branch is stacked on PR #41 until T-028 merges.
- `audit_log.id` live schema check result from Task 1.
- Policy-orchestrator vendor side effects were reordered audit-before-apply.
- Actor-only query filtering is intentionally not indexed in T-031; add `(tenant_id, actor, timestamp DESC)` or an expression index on `details->>'actor'` if SOC reports slow actor queries.
- XAI `AuditTrail` remains separate and is tracked by T-032.
- Local/project Redis audit surface check result and backfill command.
- The final squash body must retain the `BREAKING CHANGE:` footer so release-please generates the v1.1.4 operator note.

- [ ] **Step 6: Push**

Run:

```bash
git push
```

Expected: branch updates `origin/feat/phase-1-audit-log-redis-to-pg`.
