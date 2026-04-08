"""Add host_events, hardening_posture, ebpf_programs, and baseline_hashes tables.

Revision ID: 001
Revises: None
Create Date: 2026-03-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("pid", sa.Integer),
        sa.Column("uid", sa.Integer),
        sa.Column("comm", sa.String(16)),
        sa.Column("severity", sa.String(20), server_default="info"),
        sa.Column("detail", sa.JSON),
        sa.Column("hostname", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index("idx_host_events_type", "host_events", ["event_type"])
    op.create_index("idx_host_events_timestamp", "host_events", [sa.text("timestamp DESC")])
    op.create_index("idx_host_events_severity", "host_events", ["severity"])

    op.create_table(
        "hardening_posture",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("checks_run", sa.Integer, nullable=False),
        sa.Column("checks_passed", sa.Integer, nullable=False),
        sa.Column("checks_failed", sa.Integer, nullable=False),
        sa.Column("posture_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("details", sa.JSON),
        sa.Column("hostname", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index("idx_hardening_posture_timestamp", "hardening_posture", [sa.text("timestamp DESC")])

    op.create_table(
        "ebpf_programs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("prog_type", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), server_default="loaded"),
        sa.Column("loaded_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("unloaded_at", sa.DateTime(timezone=True)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index("idx_ebpf_programs_name", "ebpf_programs", ["name"])

    op.create_table(
        "baseline_hashes",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), server_default="current"),
    )
    op.create_index("idx_baseline_hashes_path", "baseline_hashes", ["file_path"])
    op.create_unique_constraint("uq_baseline_path_host", "baseline_hashes", ["file_path", "hostname"])


def downgrade() -> None:
    op.drop_table("baseline_hashes")
    op.drop_table("ebpf_programs")
    op.drop_table("hardening_posture")
    op.drop_table("host_events")
