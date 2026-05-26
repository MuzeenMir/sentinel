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

    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    if not _has_column(bind, "audit_log", "event_id"):
        # Keep id as the internal sequence key; event_id is the public replay/idempotency key.
        op.add_column(
            "audit_log",
            sa.Column(
                "event_id",
                postgresql.UUID(as_uuid=False),
                nullable=True,
            ),
        )
        op.execute("""
            UPDATE audit_log
            SET event_id = gen_random_uuid()
            WHERE event_id IS NULL
        """)
        op.alter_column(
            "audit_log",
            "event_id",
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
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
        'NULL means this audit row is not yet part of the cryptographic chain; consumers MUST treat NULL as chain verification not applicable, not as tampering.'
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
