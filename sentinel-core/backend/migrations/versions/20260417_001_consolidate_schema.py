"""Consolidate base-tables ownership under Alembic.

Revision ID: 20260417_001_consolidate_schema
Revises: 20260313_001
Create Date: 2026-04-17

T-014a / T-030 implementation. Before T-030 this revision was a `SELECT 1`
stamp marker; the post-T-014d `init.sql` still owned the foundation tables
(`users`, `token_blacklist`, `audit_log`, `compliance_assessments`), so
Alembic was not truly the source of truth for them, and
`bash sentinel-core/scripts/fresh_db_check.sh` against an empty Postgres failed
with `relation "users" does not exist` at `20260417_002_sso_scim_mfa.py:133`
because the mfa_challenges FK to `users` could not resolve.

T-030 closes that gap by giving this migration responsibility for the four
base tables nothing else creates: `users`, `token_blacklist`, `audit_log`,
`compliance_assessments`. Each creation is guarded by `if not _has_table(...)`
so the migration is a true no-op against already-bootstrapped DBs (init.sql-era
deployments, the `sentinel-internal` canary once it lands, anyone who already
ran the chain locally). Indexes use `CREATE INDEX IF NOT EXISTS` for the same
reason.

`tenants` and `policy_decisions` are deliberately *not* created here — they are
owned by `20260313_001_enterprise_schema.py`, which runs first in the chain and
creates them with `if not _has_table(...)` guards of its own. Pre-T-030
deployed DBs carry the init.sql-shipped `tenants` / `policy_decisions` schemas;
fresh DBs carry the richer 20260313_001 schemas. Both are accepted by the
runtime adapters. Touching them here would either be dead code or would
introduce a third schema variant.

`downgrade()` deliberately remains a no-op. `alembic downgrade base` should
leave the DB ready for a clean re-upgrade; if we dropped these tables on
downgrade we would have to recreate them on the immediately-following upgrade
(the idempotency guards handle that path already), and a no-op downgrade
avoids catastrophic data loss for any human who mistypes `downgrade base`
against a populated DB. T-014e's `fresh_db_check.sh` round-trip exercises this
asymmetry; it is the canonical regression gate (CI job
`integration-migrations`).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision: str = "20260417_001_consolidate_schema"
down_revision: Union[str, None] = "20260313_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(bind, name: str) -> bool:
    return inspect(bind).has_table(name)


def upgrade() -> None:
    """Create the four base tables (idempotent) previously owned by init.sql."""
    bind = op.get_bind()

    if not _has_table(bind, "users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("username", sa.String(80), nullable=False, unique=True),
            sa.Column("email", sa.String(120), nullable=False, unique=True),
            sa.Column("password_hash", sa.String(128), nullable=False),
            sa.Column(
                "role",
                sa.String(20),
                nullable=False,
                server_default=sa.text("'viewer'"),
            ),
            sa.Column(
                "status",
                sa.String(20),
                server_default=sa.text("'active'"),
            ),
            sa.Column("tenant_id", sa.BigInteger),
            sa.Column("mfa_secret", sa.String(32)),
            sa.Column(
                "mfa_enabled",
                sa.Boolean,
                server_default=sa.text("FALSE"),
            ),
            sa.Column("mfa_backup_codes", sa.Text),
            sa.Column(
                "created_at",
                sa.TIMESTAMP,
                server_default=sa.text("NOW()"),
            ),
            sa.Column("last_login", sa.TIMESTAMP),
            sa.Column(
                "failed_login_attempts",
                sa.Integer,
                server_default=sa.text("0"),
            ),
            sa.Column("locked_until", sa.TIMESTAMP),
        )

    op.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users (status)")

    if not _has_table(bind, "token_blacklist"):
        op.create_table(
            "token_blacklist",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("jti", sa.String(36), nullable=False, unique=True),
            sa.Column(
                "revoked_at",
                sa.TIMESTAMP,
                server_default=sa.text("NOW()"),
            ),
        )

    if not _has_table(bind, "audit_log"):
        op.create_table(
            "audit_log",
            sa.Column("id", sa.BigInteger, primary_key=True),
            sa.Column("tenant_id", sa.BigInteger),
            sa.Column("user_id", sa.Integer),
            sa.Column("action", sa.String(100), nullable=False),
            sa.Column("resource_type", sa.String(50)),
            sa.Column("resource_id", sa.String(100)),
            sa.Column("details", sa.dialects.postgresql.JSONB),
            sa.Column("ip_address", sa.dialects.postgresql.INET),
            sa.Column(
                "timestamp",
                sa.TIMESTAMP,
                server_default=sa.text("NOW()"),
            ),
        )

    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log (tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (user_id)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action)")

    if not _has_table(bind, "compliance_assessments"):
        op.create_table(
            "compliance_assessments",
            sa.Column("id", sa.BigInteger, primary_key=True),
            sa.Column("tenant_id", sa.BigInteger),
            sa.Column("framework", sa.String(50), nullable=False),
            sa.Column("score", sa.Float),
            sa.Column("total_controls", sa.Integer),
            sa.Column("passed_controls", sa.Integer),
            sa.Column("failed_controls", sa.Integer),
            sa.Column("details", sa.dialects.postgresql.JSONB),
            sa.Column(
                "assessed_at",
                sa.TIMESTAMP,
                server_default=sa.text("NOW()"),
            ),
        )

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_compliance_tenant ON compliance_assessments (tenant_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_assessments (framework)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_compliance_assessed ON compliance_assessments (assessed_at)"
    )


def downgrade() -> None:
    """Intentional no-op. See module docstring for the asymmetry rationale."""
    op.execute("SELECT 1")
