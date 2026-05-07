"""Add host_events, hardening_posture, ebpf_programs, and baseline_hashes tables.

Revision ID: 001
Revises: None
Create Date: 2026-03-04

Idempotency (Phase 0 slice 3):
Each CREATE TABLE is gated on a live-state check via SQLAlchemy inspector;
each index / unique constraint uses PostgreSQL's native `IF NOT EXISTS`.
This lets `alembic upgrade head` run twice on the same database without error
(required by `scripts/fresh_db_check.sh` / integration-migrations CI job).
Downgrade uses `DROP TABLE IF EXISTS` so a partially-upgraded database can
still be reset.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(bind, name: str) -> bool:
    return inspect(bind).has_table(name)


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "host_events"):
        op.create_table(
            "host_events",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "event_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("event_type", sa.String(50), nullable=False),
            sa.Column(
                "timestamp",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column("pid", sa.Integer),
            sa.Column("uid", sa.Integer),
            sa.Column("comm", sa.String(16)),
            sa.Column("severity", sa.String(20), server_default="info"),
            sa.Column("detail", sa.JSON),
            sa.Column("hostname", sa.String(255)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_events_type ON host_events (event_type)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_events_timestamp ON host_events (timestamp DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_events_severity ON host_events (severity)"
    )

    if not _has_table(bind, "hardening_posture"):
        op.create_table(
            "hardening_posture",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "scan_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column(
                "timestamp",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column("checks_run", sa.Integer, nullable=False),
            sa.Column("checks_passed", sa.Integer, nullable=False),
            sa.Column("checks_failed", sa.Integer, nullable=False),
            sa.Column("posture_score", sa.Numeric(5, 2), nullable=False),
            sa.Column("details", sa.JSON),
            sa.Column("hostname", sa.String(255)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_hardening_posture_timestamp "
        "ON hardening_posture (timestamp DESC)"
    )

    if not _has_table(bind, "ebpf_programs"):
        op.create_table(
            "ebpf_programs",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("name", sa.String(128), nullable=False),
            sa.Column("prog_type", sa.String(32), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("status", sa.String(20), server_default="loaded"),
            sa.Column(
                "loaded_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("unloaded_at", sa.DateTime(timezone=True)),
            sa.Column("hostname", sa.String(255)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_ebpf_programs_name ON ebpf_programs (name)"
    )

    if not _has_table(bind, "baseline_hashes"):
        op.create_table(
            "baseline_hashes",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("file_path", sa.String(512), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("hostname", sa.String(255)),
            sa.Column(
                "recorded_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column("verified_at", sa.DateTime(timezone=True)),
            sa.Column("status", sa.String(20), server_default="current"),
        )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_baseline_hashes_path "
        "ON baseline_hashes (file_path)"
    )
    # Unique constraint expressed as a unique index so IF NOT EXISTS applies.
    # Postgres treats this identically to ADD CONSTRAINT ... UNIQUE for
    # duplicate-row detection.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_baseline_path_host "
        "ON baseline_hashes (file_path, hostname)"
    )


def downgrade() -> None:
    # DROP TABLE CASCADE removes dependent indices and constraints; IF EXISTS
    # lets the downgrade run against a partially-upgraded database.
    op.execute("DROP TABLE IF EXISTS baseline_hashes CASCADE")
    op.execute("DROP TABLE IF EXISTS ebpf_programs CASCADE")
    op.execute("DROP TABLE IF EXISTS hardening_posture CASCADE")
    op.execute("DROP TABLE IF EXISTS host_events CASCADE")
