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
            -- not contend. The key is a full 64-bit hash of the tenant scope:
            -- this avoids the int4 ceiling of the two-arg advisory lock
            -- (tenant_id is bigint) and gives the NULL/'system' scope its own
            -- distinct key.
            PERFORM pg_advisory_xact_lock(
                hashtextextended('sentinel.audit.chain:' || COALESCE(NEW.tenant_id::text, 'system'), 0)
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
