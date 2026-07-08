"""Add node_alert_triage: the auto-triage worker's output sink.

One row per node alert: the copilot's grounded triage (text + citations +
citation provenance), the signed reversible proposal drafted for human
confirmation (JSONB, never executed by any service), and retry bookkeeping
(``status``/``attempts``) so failed inference is retried a bounded number of
times.

The worker and the gateway run as ``sentinel_app`` (NOSUPERUSER NOBYPASSRLS),
so the role gets SELECT/INSERT/UPDATE here — unlike ``node_alerts``, which
stays owner-write-only (the detector's sink, 20260703_001). DELETE is granted
to no app role: triage verdicts are part of the incident record.

Revision ID: 20260707_001_node_alert_triage
Revises: 20260703_001_node_alerts_grant
Create Date: 2026-07-07
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260707_001_node_alert_triage"
down_revision: Union[str, None] = "20260703_001_node_alerts_grant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_alert_triage",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "alert_id",
            sa.BigInteger,
            sa.ForeignKey("node_alerts.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("status", sa.String(20), server_default="triaged", nullable=False),
        sa.Column("attempts", sa.Integer, server_default="1", nullable=False),
        sa.Column("grounded", sa.Boolean),
        sa.Column("triage_text", sa.Text),
        sa.Column("citations", sa.dialects.postgresql.JSONB),
        sa.Column("citation_provenance", sa.dialects.postgresql.JSONB),
        sa.Column("proposal", sa.dialects.postgresql.JSONB),
        sa.Column("provider", sa.String(32)),
        sa.Column("model", sa.String(128)),
        sa.Column("error", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_alert_triage_status "
        "ON node_alert_triage (status)"
    )
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                GRANT SELECT, INSERT, UPDATE ON node_alert_triage TO sentinel_app;
                GRANT USAGE, SELECT ON SEQUENCE node_alert_triage_id_seq
                    TO sentinel_app;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.drop_table("node_alert_triage")
