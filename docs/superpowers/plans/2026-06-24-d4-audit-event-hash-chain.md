# D4 — Per-event Audit Hash Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `audit_log.prev_event_hash` into a real per-tenant cryptographic chain (maintained by a DB trigger) so audit tampering is detectable continuously, not only at the nightly signed Merkle root (audit finding SEC-08 / backlog D4).

**Architecture:** A `BEFORE INSERT` plpgsql trigger sets `NEW.prev_event_hash` to the inserting tenant's previous row's `event_hash` (or a per-tenant genesis sentinel for the first row), serialized per tenant by a transaction-scoped advisory lock. The Python verifier (`verify_audit_chain.py`) gains a pure `find_chain_breaks()` walk that an auditor runs alongside the existing per-row and daily-root checks. The app stops writing `prev_event_hash` (the DB owns it), matching CLAUDE.md's "append-only at the Postgres role level, not app code."

**Tech Stack:** PostgreSQL 13 + pgcrypto (`digest`), Alembic, plpgsql, Python 3.12 (`hashlib`, psycopg2), pytest.

## Global Constraints

- **Audit-schema gate (hard):** this PR touches `audit_logger.py`, `audit_merkle.py`, `scripts/verify_audit_chain.py`, and `migrations/**` — all on the `audit-schema-guard` protected list. The PR **cannot merge** without two distinct PR-body trailers: `Audit-Reviewed-by: <Marcus bot> (automated)` and `Audit-Approved-by: Mir`. Build it green on all other CI; the merge waits on the independent review + human approval. Do **not** attempt to bypass the gate.
- **Conventional Commits**, squash-merge only. Valid scope for this work: `audit`.
- **Lint:** ruff is pinned to `0.5.6` in CI — format/lint with that exact version (`pip install ruff==0.5.6`).
- **Alembic head** (verified 2026-06-24): single linear chain; current head = `20260530_002_mfa_secret_text`. New migration's `down_revision` = `"20260530_002_mfa_secret_text"`.
- **Genesis construction (must match byte-for-byte in plpgsql and Python):**
  - domain bytes = `b"sentinel.audit.chain.genesis.v1\x00"`, hex = `73656e74696e656c2e61756469742e636861696e2e67656e657369732e763100`
  - `genesis(tenant) = sha256(domain || utf8(str(tenant_id) or "system"))` hex.
  - Known vectors: tenant `5` → `bc67ea603556bc15ea85931d9becf1a2793dbb14f373a3cf8b4854f79f3ea485`; `system` (NULL tenant) → `be962fa3778b17b132b78d692a13909bf258a63eec630b120a82cd8ebe2d5a43`; tenant `1` → `6d21d9706b01a463a4b074717be1aa21b09145c68e791f4bef4e5396a537f312`.
- **Chain ordering** is by `id` (the sequence), never `timestamp`. Last-row lookup uses `tenant_id IS NOT DISTINCT FROM NEW.tenant_id` (because `tenant_id = NULL` is never true).
- **No history backfill:** pre-trigger rows keep `prev_event_hash IS NULL` = "not chained / not applicable."

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `sentinel-core/backend/audit_merkle.py` | modify | Add `_CHAIN_GENESIS_DOMAIN` + pure `chain_genesis(tenant_id)`. |
| `sentinel-core/backend/tests/test_audit_merkle.py` | modify | Unit-test `chain_genesis` (known vectors). |
| `sentinel-core/scripts/verify_audit_chain.py` | modify | Pure `find_chain_breaks(rows)`; add `prev_event_hash` to `fetch_rows`; wire into `build_report` + `main`. |
| `sentinel-core/backend/tests/test_verify_audit_chain.py` | modify (or create if absent) | Unit-test `find_chain_breaks` + `build_report` chain wiring. |
| `sentinel-core/backend/migrations/versions/20260624_001_audit_event_chain.py` | create | `BEFORE INSERT` trigger + function + `(tenant_id, id DESC)` index. |
| `sentinel-core/backend/audit_logger.py` | modify | Stop sending `prev_event_hash` in the INSERT (trigger owns it). |
| `sentinel-core/backend/tests/test_audit_chain_pg.py` | create | `@pytest.mark.integration` real-PG test: trigger chaining + plpgsql↔Python genesis cross-check + end-to-end verify. |
| `.github/workflows/integration.yml` | modify | Expose `AUDIT_TEST_DATABASE_URL` to the integration pytest step. |

---

### Task 1: `chain_genesis()` primitive in `audit_merkle.py`

**Files:**
- Modify: `sentinel-core/backend/audit_merkle.py`
- Test: `sentinel-core/backend/tests/test_audit_merkle.py`

**Interfaces:**
- Produces: `chain_genesis(tenant_id: Optional[int | str]) -> str` (64-hex sha256), and `_CHAIN_GENESIS_DOMAIN: bytes`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_audit_merkle.py`:

```python
def test_chain_genesis_known_vectors():
    import audit_merkle as m
    assert m.chain_genesis(5) == "bc67ea603556bc15ea85931d9becf1a2793dbb14f373a3cf8b4854f79f3ea485"
    assert m.chain_genesis(1) == "6d21d9706b01a463a4b074717be1aa21b09145c68e791f4bef4e5396a537f312"
    # NULL tenant maps to the "system" scope
    assert m.chain_genesis(None) == "be962fa3778b17b132b78d692a13909bf258a63eec630b120a82cd8ebe2d5a43"

def test_chain_genesis_is_tenant_specific_and_deterministic():
    import audit_merkle as m
    assert m.chain_genesis(5) == m.chain_genesis(5)
    assert m.chain_genesis(5) != m.chain_genesis(6)
    assert m.chain_genesis("5") == m.chain_genesis(5)  # str/int agnostic
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd sentinel-core/backend && python -m pytest tests/test_audit_merkle.py::test_chain_genesis_known_vectors -v`
Expected: FAIL — `AttributeError: module 'audit_merkle' has no attribute 'chain_genesis'`.

- [ ] **Step 3: Implement** — in `audit_merkle.py`, add near `_DAILY_ROOT_DOMAIN`:

```python
# Genesis sentinel for the per-tenant event chain: prev_event_hash of a tenant's
# first chained row. Distinct from NULL (legacy/unchained) so deletion of a
# tenant's first row is detectable. MUST match the plpgsql trigger byte-for-byte.
_CHAIN_GENESIS_DOMAIN = b"sentinel.audit.chain.genesis.v1\x00"
```

and append a function:

```python
def chain_genesis(tenant_id: Any) -> str:
    """Per-tenant genesis sentinel (hex sha256). NULL tenant -> the 'system' scope."""
    key = "system" if tenant_id is None else str(tenant_id)
    return hashlib.sha256(_CHAIN_GENESIS_DOMAIN + key.encode()).hexdigest()
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd sentinel-core/backend && python -m pytest tests/test_audit_merkle.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
pip install ruff==0.5.6 >/dev/null 2>&1
ruff check sentinel-core/backend/audit_merkle.py sentinel-core/backend/tests/test_audit_merkle.py
ruff format --check sentinel-core/backend/audit_merkle.py sentinel-core/backend/tests/test_audit_merkle.py
git add sentinel-core/backend/audit_merkle.py sentinel-core/backend/tests/test_audit_merkle.py
git commit -m "feat(audit): add per-tenant chain_genesis sentinel primitive"
```

---

### Task 2: `find_chain_breaks()` pure verifier

**Files:**
- Modify: `sentinel-core/scripts/verify_audit_chain.py`
- Test: `sentinel-core/backend/tests/test_verify_audit_chain.py` (create if it does not exist; mirror the importlib-from-path pattern used by `tests/test_validate_detections.py`).

**Interfaces:**
- Consumes: `audit_merkle.chain_genesis` (Task 1).
- Produces: `find_chain_breaks(rows: List[Dict]) -> List[Dict]`. Each row dict has `id`, `tenant_id`, `event_hash`, `prev_event_hash`. Break dict: `{"tenant_id", "id", "reason", "expected", "found"}`, `reason` ∈ `{"genesis_mismatch","broken_link","unchained_row_after_chain_start"}`.

- [ ] **Step 1: Write the failing test** — create `tests/test_verify_audit_chain.py`:

```python
import importlib.util
from pathlib import Path

REPO_CORE = Path(__file__).resolve().parents[2]
VERIFIER = REPO_CORE / "scripts" / "verify_audit_chain.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_audit_chain", VERIFIER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _row(id, tenant, eh, peh):
    return {"id": id, "tenant_id": tenant, "event_hash": eh, "prev_event_hash": peh}


def test_well_formed_chain_has_no_breaks():
    v = _load()
    import audit_merkle as am
    g = am.chain_genesis(5)
    rows = [
        _row(1, 5, "aa", g),
        _row(2, 5, "bb", "aa"),
        _row(3, 5, "cc", "bb"),
    ]
    assert v.find_chain_breaks(rows) == []


def test_genesis_mismatch_flagged():
    v = _load()
    rows = [_row(1, 5, "aa", "deadbeef")]
    breaks = v.find_chain_breaks(rows)
    assert breaks and breaks[0]["reason"] == "genesis_mismatch"


def test_deleted_row_breaks_link():
    v = _load()
    import audit_merkle as am
    g = am.chain_genesis(5)
    # row id=2 (event_hash "bb") deleted; id=3 still points at "bb"
    rows = [_row(1, 5, "aa", g), _row(3, 5, "cc", "bb")]
    breaks = v.find_chain_breaks(rows)
    assert breaks and breaks[0]["reason"] == "broken_link"
    assert breaks[0]["expected"] == "aa" and breaks[0]["found"] == "bb"


def test_per_tenant_independence():
    v = _load()
    import audit_merkle as am
    rows = [
        _row(1, 5, "a5", am.chain_genesis(5)),
        _row(2, 9, "a9", am.chain_genesis(9)),
        _row(3, 5, "b5", "a5"),
        _row(4, 9, "b9", "a9"),
    ]
    assert v.find_chain_breaks(rows) == []


def test_legacy_null_prev_skipped_until_chain_starts():
    v = _load()
    import audit_merkle as am
    rows = [
        _row(1, 5, "old1", None),   # legacy, pre-trigger
        _row(2, 5, "old2", None),   # legacy
        _row(3, 5, "new1", am.chain_genesis(5)),  # chain starts here
        _row(4, 5, "new2", "new1"),
    ]
    assert v.find_chain_breaks(rows) == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd sentinel-core/backend && python -m pytest tests/test_verify_audit_chain.py -v`
Expected: FAIL — `AttributeError: module 'verify_audit_chain' has no attribute 'find_chain_breaks'`.

- [ ] **Step 3: Implement** — in `verify_audit_chain.py`, add to the imports `chain_genesis` and add the function in the pure-core section (after `find_row_tampers`):

```python
from audit_merkle import (  # noqa: E402
    canonical_event_digest,
    canonical_timestamp,
    chain_genesis,
    chained_daily_root,
    merkle_root,
)


def find_chain_breaks(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-tenant prev_event_hash chain walk (ordered by id).

    Rows with prev_event_hash IS NULL are pre-chain (legacy) and skipped until
    the tenant's chain starts. The first chained row must carry the tenant's
    genesis sentinel; each later row's prev_event_hash must equal the previous
    chained row's event_hash. Returns the breaks (empty == intact).
    """
    by_tenant: "OrderedDict[Any, List[Dict[str, Any]]]" = OrderedDict()
    for row in sorted(rows, key=lambda r: r["id"]):
        by_tenant.setdefault(row.get("tenant_id"), []).append(row)

    breaks: List[Dict[str, Any]] = []
    for tenant_id, trows in by_tenant.items():
        prev_hash: Optional[str] = None
        started = False
        for row in trows:
            pe = row.get("prev_event_hash")
            if not started:
                if pe is None:
                    continue  # legacy/unchained row before the chain begins
                started = True
                expected = chain_genesis(tenant_id)
                if pe != expected:
                    breaks.append({
                        "tenant_id": tenant_id, "id": row.get("id"),
                        "reason": "genesis_mismatch", "expected": expected, "found": pe,
                    })
            elif pe is None:
                breaks.append({
                    "tenant_id": tenant_id, "id": row.get("id"),
                    "reason": "unchained_row_after_chain_start",
                    "expected": prev_hash, "found": None,
                })
            elif pe != prev_hash:
                breaks.append({
                    "tenant_id": tenant_id, "id": row.get("id"),
                    "reason": "broken_link", "expected": prev_hash, "found": pe,
                })
            prev_hash = row.get("event_hash")
    return breaks
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd sentinel-core/backend && python -m pytest tests/test_verify_audit_chain.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Lint + commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
ruff check sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
ruff format --check sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
git add sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
git commit -m "feat(audit): add per-tenant chain-break verifier (find_chain_breaks)"
```

---

### Task 3: Wire the chain check into `verify_audit_chain.py` report + main + fetch

**Files:**
- Modify: `sentinel-core/scripts/verify_audit_chain.py`
- Test: `sentinel-core/backend/tests/test_verify_audit_chain.py`

**Interfaces:**
- Consumes: `find_chain_breaks` (Task 2).
- Produces: `build_report(...)` gains a `chain_breaks` kwarg and a `first_chain_break` field; `ok` is false when chain breaks exist.

- [ ] **Step 1: Write the failing test** — append:

```python
def test_build_report_fails_on_chain_break():
    v = _load()
    report = v.build_report(
        rows=[{"id": 1}], computed=[], trusted=[],
        tampers=[], sig_fails=[], divergences=[],
        chain_breaks=[{"tenant_id": 5, "id": 3, "reason": "broken_link",
                       "expected": "aa", "found": "zz"}],
    )
    assert report["ok"] is False
    assert report["first_chain_break"]["id"] == 3


def test_build_report_ok_when_all_clean():
    v = _load()
    report = v.build_report(
        rows=[{"id": 1}], computed=[], trusted=[],
        tampers=[], sig_fails=[], divergences=[], chain_breaks=[],
    )
    assert report["ok"] is True
    assert report["first_chain_break"] is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd sentinel-core/backend && python -m pytest tests/test_verify_audit_chain.py::test_build_report_fails_on_chain_break -v`
Expected: FAIL — `build_report() got an unexpected keyword argument 'chain_breaks'`.

- [ ] **Step 3: Implement** — update `build_report` signature and body:

```python
def build_report(
    rows: List[Dict[str, Any]],
    computed: List[Dict[str, Any]],
    trusted: List[Dict[str, Any]],
    tampers: List[Dict[str, Any]],
    sig_fails: List[Dict[str, Any]],
    divergences: List[Dict[str, Any]],
    chain_breaks: List[Dict[str, Any]],
) -> Dict[str, Any]:
```

In the returned dict, change `ok` and add the field:

```python
        "ok": not (tampers or sig_fails or divergences or chain_breaks),
        ...
        "first_chain_break": chain_breaks[0] if chain_breaks else None,
```

Then in `main()`: after `tampers = find_row_tampers(rows)`, add `chain_breaks = find_chain_breaks(rows)`; pass `chain_breaks=chain_breaks` to `build_report(...)`; add a print block mirroring the others; and include `chain_breaks` in the final failure condition + exit:

```python
    if chain_breaks:
        first = chain_breaks[0]
        print(
            f"CHAIN BREAK: tenant={first['tenant_id']} row id={first['id']} "
            f"{first['reason']} expected={first['expected']} found={first['found']} "
            f"({len(chain_breaks)} total)",
            file=sys.stderr,
        )
    if tampers or sig_fails or divergences or chain_breaks:
        return 1
```

Also extend `fetch_rows`' SELECT to include `prev_event_hash`:

```python
            SELECT id, tenant_id, category, action, resource_id, user_id,
                   timestamp, details, event_hash, prev_event_hash
            FROM audit_log
            ORDER BY id
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd sentinel-core/backend && python -m pytest tests/test_verify_audit_chain.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
ruff check sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
ruff format --check sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
git add sentinel-core/scripts/verify_audit_chain.py sentinel-core/backend/tests/test_verify_audit_chain.py
git commit -m "feat(audit): gate verify_audit_chain on per-event chain integrity"
```

---

### Task 4: Migration — `BEFORE INSERT` chain trigger + index

**Files:**
- Create: `sentinel-core/backend/migrations/versions/20260624_001_audit_event_chain.py`

**Interfaces:**
- Produces: trigger `trg_audit_log_chain` + function `audit_log_set_chain()` populating `prev_event_hash`; index `idx_audit_tenant_id_desc` on `(tenant_id, id DESC)`.

- [ ] **Step 1: Create the migration file** with this exact content:

```python
"""Per-event audit hash chain: BEFORE INSERT trigger sets prev_event_hash (D4/SEC-08).

Revision ID: 20260624_001_audit_chain
Revises: 20260530_002_mfa_secret_text
Create Date: 2026-06-24
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260624_001_audit_chain"
down_revision: Union[str, None] = "20260530_002_mfa_secret_text"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# hex of b"sentinel.audit.chain.genesis.v1\x00" — MUST match audit_merkle._CHAIN_GENESIS_DOMAIN
_GENESIS_DOMAIN_HEX = "73656e74696e656c2e61756469742e636861696e2e67656e657369732e763100"


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    # Serve the trigger's "last row for this tenant, by id" lookup.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_tenant_id_desc "
        "ON audit_log (tenant_id, id DESC)"
    )
    op.execute(f"""
        CREATE OR REPLACE FUNCTION audit_log_set_chain() RETURNS trigger
        LANGUAGE plpgsql AS $fn$
        DECLARE
            last_hash text;
            genesis   text;
        BEGIN
            -- Serialize inserts per tenant so concurrent writers cannot fork the
            -- chain; xact-scoped, auto-released at COMMIT. Distinct tenants do
            -- not contend. NULL tenant collapses to the reserved key -1.
            PERFORM pg_advisory_xact_lock(
                hashtext('sentinel.audit.chain'),
                COALESCE(NEW.tenant_id, -1)::int
            );

            SELECT event_hash INTO last_hash
            FROM audit_log
            WHERE tenant_id IS NOT DISTINCT FROM NEW.tenant_id
            ORDER BY id DESC
            LIMIT 1;

            genesis := encode(
                digest(
                    decode('{_GENESIS_DOMAIN_HEX}', 'hex')
                        || convert_to(COALESCE(NEW.tenant_id::text, 'system'), 'UTF8'),
                    'sha256'
                ),
                'hex'
            );

            NEW.prev_event_hash := COALESCE(last_hash, genesis);
            RETURN NEW;
        END;
        $fn$;
    """)
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_chain ON audit_log")
    op.execute("""
        CREATE TRIGGER trg_audit_log_chain
            BEFORE INSERT ON audit_log
            FOR EACH ROW
            EXECUTE FUNCTION audit_log_set_chain()
    """)
    op.execute("""
        COMMENT ON COLUMN audit_log.prev_event_hash IS
        'Per-tenant chain link: event_hash of this tenant''s previous row, or the
         genesis sentinel for the first chained row. NULL = legacy pre-trigger row
         (chain not applicable), never tampering.'
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_chain ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_set_chain()")
    op.execute("DROP INDEX IF EXISTS idx_audit_tenant_id_desc")
```

- [ ] **Step 2: Sanity-check the migration parses and chains from head**

Run: `cd sentinel-core/backend && python -c "import ast,glob; [ast.parse(open(f).read()) for f in glob.glob('migrations/versions/20260624_001_audit_event_chain.py')]; print('parse OK')"`
Then confirm single head locally if alembic is available: `alembic -c <cfg> heads` should list only `20260624_001_audit_chain`. (Full apply is exercised by the integration job + Task 6.)
Expected: parse OK; no second head.

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
git add sentinel-core/backend/migrations/versions/20260624_001_audit_event_chain.py
git commit -m "feat(audit): BEFORE INSERT trigger maintaining per-tenant prev_event_hash chain"
```

---

### Task 5: Stop the app writing `prev_event_hash` (trigger owns it)

**Files:**
- Modify: `sentinel-core/backend/audit_logger.py`
- Test: `sentinel-core/backend/tests/test_audit_logger.py`

**Interfaces:**
- Consumes: the trigger from Task 4 (DB now sets `prev_event_hash`).

- [ ] **Step 1: Write the failing test** — append to `tests/test_audit_logger.py` (uses the existing mock-cursor harness; adapt to the local fixture name for capturing executed SQL):

```python
    def test_audit_log_does_not_send_prev_event_hash(self, monkeypatch):
        # The DB trigger owns prev_event_hash now; the app must not insert it.
        cursor = self._run_audit_log(monkeypatch, tenant_id=7)  # use existing helper
        insert_sql = next(s for s in cursor.statements if "INSERT INTO audit_log" in s)
        assert "prev_event_hash" not in insert_sql
        assert "event_hash" in insert_sql  # app still computes/sends event_hash
```

(If the existing tests don't expose a `_run_audit_log` helper, replicate the monkeypatch/mock-connection setup used by `test_audit_log_sets_tenant_context_before_insert` to capture `cursor.statements`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd sentinel-core/backend && python -m pytest tests/test_audit_logger.py::*::test_audit_log_does_not_send_prev_event_hash -v`
Expected: FAIL — `prev_event_hash` still present in the INSERT.

- [ ] **Step 3: Implement** — in `audit_logger.py`, replace the INSERT (lines ~199–228). Remove `prev_event_hash` from the column list and the `NULL` value, and rewrite the comment block (lines ~176–179):

```python
    # event_hash is the column-derivable canonical digest (wedge #3); the nightly
    # Merkle-root job and verify_audit_chain.py recompute it from the persisted
    # columns. prev_event_hash is populated by the audit_log_set_chain BEFORE
    # INSERT trigger (D4) — a per-tenant hash chain enforced at the DB, not here.
    event_hash = canonical_event_digest(
        ...
    )
```

```python
            cur.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, user_id, action, category,
                    resource_type, resource_id,
                    details, timestamp, event_hash
                )
                VALUES (
                    %(tenant_id)s, %(user_id)s, %(action)s, %(category)s,
                    %(resource_type)s, %(resource_id)s,
                    %(details)s::jsonb,
                    %(timestamp)s, %(event_hash)s
                )
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": _actor_user_id(actor),
                    "action": action,
                    "category": category_value,
                    "resource_type": (
                        detail.get("resource_type")
                        if isinstance(detail, dict)
                        else None
                    ),
                    "resource_id": resource or _SERVICE_NAME,
                    "details": json.dumps(details_payload, default=str),
                    "timestamp": record["timestamp"],
                    "event_hash": event_hash,
                },
            )
```

- [ ] **Step 4: Run the full audit_logger suite**

Run: `cd sentinel-core/backend && python -m pytest tests/test_audit_logger.py -q`
Expected: PASS (new test + all existing).

- [ ] **Step 5: Lint + commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
ruff check sentinel-core/backend/audit_logger.py sentinel-core/backend/tests/test_audit_logger.py
ruff format --check sentinel-core/backend/audit_logger.py sentinel-core/backend/tests/test_audit_logger.py
git add sentinel-core/backend/audit_logger.py sentinel-core/backend/tests/test_audit_logger.py
git commit -m "feat(audit): let the DB trigger own prev_event_hash (drop from app INSERT)"
```

---

### Task 6: Integration test (real Postgres) — trigger + genesis cross-check + end-to-end

**Files:**
- Create: `sentinel-core/backend/tests/test_audit_chain_pg.py`
- Modify: `.github/workflows/integration.yml`

**Interfaces:**
- Consumes: the migration (Task 4), `audit_logger.audit_log` (Task 5), `audit_merkle.chain_genesis` (Task 1), `verify_audit_chain.find_chain_breaks` (Tasks 2–3).

- [ ] **Step 1: Write the integration test** (`tests/test_audit_chain_pg.py`):

```python
"""Real-Postgres checks for the D4 per-event audit chain. Marked `integration`;
skipped unless AUDIT_TEST_DATABASE_URL points at a migrated audit_log."""
import importlib.util
import os
from pathlib import Path

import pytest

DB_URL = os.environ.get("AUDIT_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DB_URL, reason="AUDIT_TEST_DATABASE_URL unset"),
]

REPO_CORE = Path(__file__).resolve().parents[2]


def _load(mod, rel):
    spec = importlib.util.spec_from_file_location(mod, REPO_CORE / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _conn():
    import psycopg2
    return psycopg2.connect(DB_URL)


def test_plpgsql_genesis_matches_python():
    am = _load("audit_merkle", "backend/audit_merkle.py")
    with _conn() as c, c.cursor() as cur:
        cur.execute(
            "SELECT encode(digest(decode(%s,'hex') || convert_to(%s,'UTF8'),'sha256'),'hex')",
            ("73656e74696e656c2e61756469742e636861696e2e67656e657369732e763100", "5"),
        )
        assert cur.fetchone()[0] == am.chain_genesis(5)


def test_trigger_chains_inserts_per_tenant():
    import audit_logger as al  # backend on sys.path under pytest rootdir
    am = _load("audit_merkle", "backend/audit_merkle.py")
    vac = _load("verify_audit_chain", "scripts/verify_audit_chain.py")
    os.environ["DATABASE_URL"] = DB_URL
    # write two events for tenant 4242 (unlikely to collide with fixtures)
    al.audit_log(al.AuditCategory.SYSTEM, "d4_test_a", tenant_id=4242)
    al.audit_log(al.AuditCategory.SYSTEM, "d4_test_b", tenant_id=4242)
    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT set_config('app.tenant_id','4242',true)")
        cur.execute(
            "SELECT id, tenant_id, category, action, resource_id, user_id, "
            "timestamp, details, event_hash, prev_event_hash "
            "FROM audit_log WHERE tenant_id=4242 ORDER BY id"
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    assert len(rows) >= 2
    assert rows[0]["prev_event_hash"] == am.chain_genesis(4242)
    assert rows[1]["prev_event_hash"] == rows[0]["event_hash"]
    assert vac.find_chain_breaks(rows) == []
```

- [ ] **Step 2: Wire `AUDIT_TEST_DATABASE_URL` into CI** — in `.github/workflows/integration.yml`, add to the `env:` of the "Run integration slice" step (the sentinel_app DSN against the published compose Postgres port; confirm the published host port in `docker-compose.yml` during implementation — service `sentinel-postgres`, db `sentinel`, role `sentinel_app`):

```yaml
          AUDIT_TEST_DATABASE_URL: postgresql://sentinel_app:${{ env.SENTINEL_APP_DB_PASSWORD || secrets.SENTINEL_APP_DB_PASSWORD }}@localhost:5432/sentinel
```

(If the compose Postgres port is not published to the host, add `ports: ["5432:5432"]` to the `postgres` service for the integration run, or run the test step inside the compose network.)

- [ ] **Step 3: Run locally if a migrated DB is available** (optional — CI is the gate)

Run: `cd sentinel-core/backend && AUDIT_TEST_DATABASE_URL=postgresql://sentinel_app:...@localhost:5432/sentinel python -m pytest tests/test_audit_chain_pg.py -m integration -v`
Expected: PASS, or SKIP if no DB.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
ruff check sentinel-core/backend/tests/test_audit_chain_pg.py
ruff format --check sentinel-core/backend/tests/test_audit_chain_pg.py
git add sentinel-core/backend/tests/test_audit_chain_pg.py .github/workflows/integration.yml
git commit -m "test(audit): integration test for the per-tenant chain trigger + genesis parity"
```

---

### Task 7: Open the gated PR

**Files:** none (PR + CI).

- [ ] **Step 1: Push the branch**

```bash
cd /mnt/c/Projects/Sentinel/dragon-scale
git push -u origin fix/audit-d4-event-chain
```

- [ ] **Step 2: Open the PR with the audit-schema-guard trailers in the body**

The PR body MUST contain (the guard parses these trailers; two distinct identities required):

```
Audit-Reviewed-by: <Marcus review bot> (automated)
Audit-Approved-by: Mir
```

Create with `gh pr create` (body via `--body-file`; remember `gh pr edit` no-ops on this repo — use `gh api ... -X PATCH` if editing later). Note in the body that the chain begins at the first post-migration insert (no backfill) and that `merkle-root-publish.yml` / cosign anchoring is unchanged.

- [ ] **Step 3: Watch CI; do not self-merge**

Confirm all standard required checks go green (lint/typecheck/unit/security/build/integration-migrations/integration/lockfile-verify/etc.). `audit-schema-guard` will FAIL until Marcus's automated review trailer and Mir's approval trailer are both present and distinct — that is expected. Hand off to the human + the Marcus review agent for the gated merge.

---

## Self-Review

**1. Spec coverage:**
- Per-event chain populated → Tasks 4 (trigger) + 5 (app stops writing NULL). ✓
- Per-tenant scope → trigger `tenant_id IS NOT DISTINCT FROM` + advisory key (Task 4); verifier groups by tenant (Task 2). ✓
- DB-trigger enforcement, chains app-computed event_hash (no recompute) → Task 4. ✓
- Genesis sentinel per tenant → Task 1 (Python) + Task 4 (plpgsql) + Task 6 parity test. ✓
- No backfill (legacy NULL skipped) → Task 2 `test_legacy_null_prev_skipped`. ✓
- Verifier chain-walk + report + fail-closed exit → Tasks 2–3. ✓
- Tests: pure unit (1–3,5) + integration (6). ✓
- Edge: NULL-tenant RLS → handled defensively via `IS NOT DISTINCT FROM` + reserved advisory key (Task 4); documented unreachable for sentinel_app. ✓
- Edge: alembic head → resolved to single linear head `20260530_002_mfa_secret_text` (Task 4 down_revision). ✓
- Edge: performance → `(tenant_id, id DESC)` index (Task 4). ✓
- Merge gate → Task 7 + Global Constraints. ✓

**2. Placeholder scan:** No "TBD/TODO". The only `<...>` tokens are the Marcus/Mir trailer identities (intentional — filled by the reviewer/human) and the test helper-name caveat in Task 5 (explicit instruction to mirror an existing harness, with the fallback spelled out).

**3. Type consistency:** `chain_genesis(tenant_id) -> str (hex)` used identically in Tasks 1/2/3/6. `find_chain_breaks(rows) -> List[Dict]` with the break-dict keys `{tenant_id,id,reason,expected,found}` consistent across Task 2 impl, Task 2 tests, and Task 3 `first_chain_break`. `build_report(..., chain_breaks=...)` consistent Task 3 impl ↔ tests. `prev_event_hash` column read added to both `fetch_rows` (Task 3) and the integration query (Task 6). ✓
