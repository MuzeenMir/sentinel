"""Add node_alerts: the migration-owned alert sink for the offline node path.

Revision ID: 20260627_001_node_alerts
Revises: 20260624_001_audit_chain
Create Date: 2026-06-27
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260627_001_node_alerts"
down_revision: Union[str, None] = "20260624_001_audit_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node_alerts",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "alert_id",
            sa.dialects.postgresql.UUID,
            server_default=sa.text("gen_random_uuid()"),
            unique=True,
            nullable=False,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), server_default="medium", nullable=False),
        sa.Column("score", sa.Numeric(5, 4)),
        sa.Column("pid", sa.Integer),
        sa.Column("uid", sa.Integer),
        sa.Column("comm", sa.String(64)),
        sa.Column("exe", sa.String(512)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("source_event_id", sa.String(128)),
        sa.Column("summary", sa.Text),
        sa.Column("detail", sa.dialects.postgresql.JSONB),
        sa.Column("status", sa.String(20), server_default="new", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_alerts_created_at "
        "ON node_alerts (created_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_node_alerts_severity "
        "ON node_alerts (severity)"
    )


def downgrade() -> None:
    op.drop_table("node_alerts")
