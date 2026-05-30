"""Add dedicated reversible enforcement action records.

Revision ID: 20260530_001_reversible_enf
Revises: 20260526_001_audit_pg
Create Date: 2026-05-30

Decision: create a dedicated ``enforcement_actions`` table instead of extending
``policy_decisions``. Policy decisions are existing tenant-scoped decision data,
while reversible enforcement needs a narrow hot table scanned by the TTL reaper
with ``(rollback_state, expires_at)``. Keeping side-effect rollback state here
avoids broad reads and updates against the decision table.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision: str = "20260530_001_reversible_enf"
down_revision: Union[str, None] = "20260526_001_audit_pg"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _has_table(bind, table: str) -> bool:
    return inspect(bind).has_table(table)


def _has_column(bind, table: str, column: str) -> bool:
    return column in {c["name"] for c in inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "enforcement_actions"):
        op.create_table(
            "enforcement_actions",
            sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column("tenant_id", sa.BigInteger(), nullable=True),
            sa.Column("action_id", sa.String(64), nullable=False),
            sa.Column("policy_id", sa.String(80), nullable=False),
            sa.Column("vendor_name", sa.String(80), nullable=False),
            sa.Column(
                "rules",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column(
                "apply_result",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
            sa.Column(
                "confirmed_permanent",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("reverted_at", sa.TIMESTAMP(timezone=True), nullable=True),
            sa.Column("revert_reason", sa.Text(), nullable=True),
            sa.Column(
                "rollback_state",
                sa.String(20),
                nullable=False,
                server_default=sa.text("'pending'"),
            ),
            sa.Column(
                "retry_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("next_retry_at", sa.TIMESTAMP(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.Column(
                "updated_at",
                sa.TIMESTAMP(timezone=True),
                nullable=False,
                server_default=sa.text("NOW()"),
            ),
            sa.CheckConstraint(
                "rollback_state IN ('pending', 'active', 'reverted', 'confirmed', 'revert_failed')",
                name="ck_enforcement_actions_rollback_state",
            ),
        )
    else:
        for column, ddl in {
            "expires_at": "ALTER TABLE enforcement_actions ADD COLUMN expires_at TIMESTAMPTZ NULL",
            "confirmed_permanent": (
                "ALTER TABLE enforcement_actions ADD COLUMN "
                "confirmed_permanent BOOLEAN NOT NULL DEFAULT false"
            ),
            "reverted_at": "ALTER TABLE enforcement_actions ADD COLUMN reverted_at TIMESTAMPTZ NULL",
            "revert_reason": "ALTER TABLE enforcement_actions ADD COLUMN revert_reason TEXT NULL",
            "rollback_state": (
                "ALTER TABLE enforcement_actions ADD COLUMN rollback_state "
                "VARCHAR(20) NOT NULL DEFAULT 'pending'"
            ),
            "retry_count": (
                "ALTER TABLE enforcement_actions ADD COLUMN retry_count "
                "INTEGER NOT NULL DEFAULT 0"
            ),
            "next_retry_at": "ALTER TABLE enforcement_actions ADD COLUMN next_retry_at TIMESTAMPTZ NULL",
            "updated_at": (
                "ALTER TABLE enforcement_actions ADD COLUMN updated_at "
                "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
            ),
        }.items():
            if not _has_column(bind, "enforcement_actions", column):
                op.execute(ddl)

    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_enforcement_actions_action_id "
        "ON enforcement_actions (action_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_enforcement_actions_reaper "
        "ON enforcement_actions (rollback_state, expires_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_enforcement_actions_tenant "
        "ON enforcement_actions (tenant_id)"
    )

    op.execute("ALTER TABLE enforcement_actions ENABLE ROW LEVEL SECURITY")
    op.execute(
        "DROP POLICY IF EXISTS rls_enforcement_actions_tenant ON enforcement_actions"
    )
    op.execute("""
        CREATE POLICY rls_enforcement_actions_tenant ON enforcement_actions
          USING (tenant_id = current_setting('app.tenant_id', true)::bigint)
          WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::bigint)
    """)

    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON enforcement_actions TO sentinel_app;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;
            END IF;
        END
        $$;
    """)

    op.execute("""
        COMMENT ON TABLE enforcement_actions IS
        'Durable rollback contract for firewall enforcement side effects. Expired active rows are auto-reverted unless confirmed permanent by an admin.'
    """)


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS rls_enforcement_actions_tenant ON enforcement_actions"
    )
    op.execute("DROP INDEX IF EXISTS idx_enforcement_actions_tenant")
    op.execute("DROP INDEX IF EXISTS idx_enforcement_actions_reaper")
    op.execute("DROP INDEX IF EXISTS uq_enforcement_actions_action_id")
    op.drop_table("enforcement_actions")
