"""Enterprise schema: tenants, policy decisions, XAI audit, hardening state, data retention.

Adds multi-tenancy foundation (tenants table + tenant_id FK on core tables),
persistent tables for data currently stored in Redis (policy decisions,
XAI explanations, DRL experiences), and data retention support.

Revision ID: 20260313_001

Note on idempotency: this migration runs against a database bootstrapped by
`init.sql`, which already creates `tenants` and `policy_decisions` (see
DB-MIGRATION-DRIFT-AUDIT.md). It also references core tables (`alerts`,
`threats`, `firewall_policies`, etc.) that do not yet exist in any schema
bootstrap. We therefore inspect live state and only create/alter what is
missing, skip what is not present, and define the `update_updated_at_column`
helper before any trigger depends on it.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260313_001"
down_revision = "001"
branch_labels = None
depends_on = None


def _has_table(bind, name: str) -> bool:
    return inspect(bind).has_table(name)


def _has_column(bind, table: str, column: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(c["name"] == column for c in inspect(bind).get_columns(table))


def upgrade():
    bind = op.get_bind()

    # ── Helper function for updated_at triggers ──────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # ── Tenants (created by init.sql — skip if present) ──────────────
    if not _has_table(bind, "tenants"):
        op.create_table(
            "tenants",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "tenant_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("name", sa.String(200), nullable=False, unique=True),
            sa.Column("display_name", sa.String(200)),
            sa.Column("status", sa.String(20), server_default="active", nullable=False),
            sa.Column(
                "plan", sa.String(50), server_default="professional", nullable=False
            ),
            sa.Column("settings", sa.dialects.postgresql.JSONB, server_default="{}"),
            sa.Column("data_region", sa.String(50), server_default="us-east-1"),
            sa.Column("retention_days", sa.Integer, server_default="90"),
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
            sa.CheckConstraint(
                "status IN ('active', 'suspended', 'deactivated')",
                name="ck_tenants_status",
            ),
            sa.CheckConstraint(
                "plan IN ('basic', 'professional', 'enterprise')",
                name="ck_tenants_plan",
            ),
        )

    # Default tenant row (safe with init.sql schema — name is UNIQUE there too).
    # init.sql declares tenant_id as NOT NULL with no server default, so we
    # must populate it explicitly; gen_random_uuid() is built into Postgres
    # 13+ and its UUID return value casts cleanly into init.sql's VARCHAR(36)
    # column as well as the migration-created UUID column.
    op.execute("""
        INSERT INTO tenants (tenant_id, name, display_name, plan)
        VALUES (gen_random_uuid(), 'default', 'Default Organization', 'enterprise')
        ON CONFLICT (name) DO NOTHING
    """)

    # ── Add tenant_id to existing core tables ────────────────────────
    # Only touch tables that actually exist in this database — several
    # of these are created by services at runtime and are not guaranteed
    # to be present when db-migrate runs on a fresh volume.
    for table in [
        "alerts",
        "threats",
        "firewall_policies",
        "network_logs",
        "compliance_assessments",
        "audit_logs",
        "training_data",
        "rl_agent_states",
        "system_config",
    ]:
        if not _has_table(bind, table):
            continue
        if not _has_column(bind, table, "tenant_id"):
            op.add_column(table, sa.Column("tenant_id", sa.BigInteger, nullable=True))
        op.execute(f"""
            UPDATE {table} SET tenant_id = (SELECT id FROM tenants WHERE name = 'default')
            WHERE tenant_id IS NULL
        """)
        op.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant_id ON {table} (tenant_id)"
        )

    # ── Policy decisions (init.sql ships a simpler version) ─────────
    if not _has_table(bind, "policy_decisions"):
        op.create_table(
            "policy_decisions",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "decision_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("threat_id", sa.BigInteger, nullable=True),
            sa.Column("source_ip", sa.dialects.postgresql.INET),
            sa.Column("dest_ip", sa.dialects.postgresql.INET),
            sa.Column("action", sa.String(30), nullable=False),
            sa.Column("confidence", sa.Numeric(5, 4)),
            sa.Column("model_version", sa.String(50)),
            sa.Column("state_vector", sa.dialects.postgresql.JSONB),
            sa.Column("reward", sa.Numeric(8, 4)),
            sa.Column("policy_id", sa.BigInteger, nullable=True),
            sa.Column("applied", sa.Boolean, server_default="false"),
            sa.Column("applied_at", sa.DateTime(timezone=True)),
            sa.Column("rolled_back", sa.Boolean, server_default="false"),
            sa.Column("rolled_back_at", sa.DateTime(timezone=True)),
            sa.Column("details", sa.dialects.postgresql.JSONB),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.CheckConstraint(
                "action IN ('ALLOW', 'DENY', 'RATE_LIMIT', 'QUARANTINE', 'MONITOR')",
                name="ck_policy_decisions_action",
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_tenant ON policy_decisions (tenant_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_created ON policy_decisions (created_at DESC)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_action ON policy_decisions (action)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_policy_decisions_source ON policy_decisions (source_ip)"
        )

    # ── XAI explanations ────────────────────────────────────────────
    if not _has_table(bind, "xai_explanations"):
        op.create_table(
            "xai_explanations",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "explanation_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("detection_id", sa.String(200)),
            sa.Column("decision_id", sa.BigInteger, nullable=True),
            sa.Column("explanation_type", sa.String(30), nullable=False),
            sa.Column("model_name", sa.String(100)),
            sa.Column("feature_importances", sa.dialects.postgresql.JSONB),
            sa.Column("shap_values", sa.dialects.postgresql.JSONB),
            sa.Column("natural_language", sa.Text),
            sa.Column("risk_factors", sa.dialects.postgresql.JSONB),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.CheckConstraint(
                "explanation_type IN ('detection', 'policy', 'compliance')",
                name="ck_xai_explanations_type",
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_xai_explanations_tenant ON xai_explanations (tenant_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_xai_explanations_detection ON xai_explanations (detection_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_xai_explanations_created ON xai_explanations (created_at DESC)"
        )

    # ── Hardening scan results (persistent) ──────────────────────────
    if not _has_table(bind, "hardening_scans"):
        op.create_table(
            "hardening_scans",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "scan_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("hostname", sa.String(255)),
            sa.Column("checks_run", sa.Integer, nullable=False),
            sa.Column("checks_passed", sa.Integer, nullable=False),
            sa.Column("checks_failed", sa.Integer, nullable=False),
            sa.Column("posture_score", sa.Numeric(5, 2)),
            sa.Column("results", sa.dialects.postgresql.JSONB),
            sa.Column("remediations_applied", sa.Integer, server_default="0"),
            sa.Column(
                "scanned_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hardening_scans_tenant ON hardening_scans (tenant_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hardening_scans_hostname ON hardening_scans (hostname)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hardening_scans_scanned ON hardening_scans (scanned_at DESC)"
        )

    # ── HIDS events (persistent, time-series) ────────────────────────
    if not _has_table(bind, "hids_events"):
        op.create_table(
            "hids_events",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "event_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("hostname", sa.String(255)),
            sa.Column("event_type", sa.String(50), nullable=False),
            sa.Column("severity", sa.String(20), server_default="medium"),
            sa.Column("pid", sa.Integer),
            sa.Column("uid", sa.Integer),
            sa.Column("comm", sa.String(255)),
            sa.Column("filename", sa.String(1024)),
            sa.Column("details", sa.dialects.postgresql.JSONB),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hids_events_tenant ON hids_events (tenant_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hids_events_type ON hids_events (event_type)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hids_events_severity ON hids_events (severity)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hids_events_created ON hids_events (created_at DESC)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_hids_events_hostname_time ON hids_events (hostname, created_at DESC)"
        )

    # ── Integration / webhook registry ───────────────────────────────
    if not _has_table(bind, "integrations"):
        op.create_table(
            "integrations",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "integration_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("type", sa.String(50), nullable=False),
            sa.Column("config", sa.dialects.postgresql.JSONB, server_default="{}"),
            sa.Column("is_active", sa.Boolean, server_default="true"),
            sa.Column("last_triggered_at", sa.DateTime(timezone=True)),
            sa.Column("failure_count", sa.Integer, server_default="0"),
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
            sa.CheckConstraint(
                "type IN ('webhook', 'siem_splunk', 'siem_elastic', 'siem_sentinel', "
                "'soar_xsoar', 'soar_tines', 'ticketing_servicenow', 'ticketing_jira', 'email', 'slack', 'custom')",
                name="ck_integrations_type",
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations (tenant_id)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations (type)"
        )

    # ── Model registry ──────────────────────────────────────────────
    if not _has_table(bind, "model_registry"):
        op.create_table(
            "model_registry",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column(
                "model_id",
                sa.dialects.postgresql.UUID,
                server_default=sa.text("gen_random_uuid()"),
                unique=True,
                nullable=False,
            ),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("version", sa.String(50), nullable=False),
            sa.Column("model_type", sa.String(50), nullable=False),
            sa.Column("framework", sa.String(50)),
            sa.Column("artifact_path", sa.String(500)),
            sa.Column("metrics", sa.dialects.postgresql.JSONB),
            sa.Column("parameters", sa.dialects.postgresql.JSONB),
            sa.Column("status", sa.String(20), server_default="staging"),
            sa.Column("promoted_at", sa.DateTime(timezone=True)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.UniqueConstraint(
                "name", "version", name="uq_model_registry_name_version"
            ),
            sa.CheckConstraint(
                "status IN ('staging', 'production', 'archived', 'failed')",
                name="ck_model_registry_status",
            ),
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_registry_name ON model_registry (name)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS idx_model_registry_status ON model_registry (status)"
        )

    # ── Data retention configuration per tenant ──────────────────────
    if not _has_table(bind, "data_retention_policies"):
        op.create_table(
            "data_retention_policies",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("tenant_id", sa.BigInteger, nullable=True),
            sa.Column("table_name", sa.String(100), nullable=False),
            sa.Column("retention_days", sa.Integer, nullable=False),
            sa.Column("archive_to_s3", sa.Boolean, server_default="false"),
            sa.Column("s3_bucket", sa.String(200)),
            sa.Column("last_purged_at", sa.DateTime(timezone=True)),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.UniqueConstraint(
                "tenant_id", "table_name", name="uq_retention_tenant_table"
            ),
        )

    op.execute("""
        INSERT INTO data_retention_policies (tenant_id, table_name, retention_days)
        SELECT t.id, tbl.name, tbl.days
        FROM tenants t, (VALUES
            ('network_logs', 30),
            ('alerts', 90),
            ('threats', 180),
            ('audit_logs', 365),
            ('hids_events', 60),
            ('policy_decisions', 90),
            ('xai_explanations', 90),
            ('hardening_scans', 180)
        ) AS tbl(name, days)
        WHERE t.name = 'default'
        ON CONFLICT DO NOTHING
    """)

    # ── Updated-at trigger for tables that have updated_at ───────────
    # init.sql's `tenants` has updated_at; integrations is created above
    # with updated_at. Only create the trigger if the column exists and
    # the trigger does not already exist.
    for table in ["tenants", "integrations"]:
        if _has_column(bind, table, "updated_at"):
            op.execute(f"DROP TRIGGER IF EXISTS update_{table}_updated_at ON {table}")
            op.execute(f"""
                CREATE TRIGGER update_{table}_updated_at
                    BEFORE UPDATE ON {table}
                    FOR EACH ROW
                    EXECUTE FUNCTION update_updated_at_column()
            """)


def downgrade():
    for table in [
        "data_retention_policies",
        "model_registry",
        "integrations",
        "hids_events",
        "hardening_scans",
        "xai_explanations",
    ]:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")

    for table in [
        "alerts",
        "threats",
        "firewall_policies",
        "network_logs",
        "compliance_assessments",
        "audit_logs",
        "training_data",
        "rl_agent_states",
        "system_config",
    ]:
        op.execute(f"ALTER TABLE IF EXISTS {table} DROP COLUMN IF EXISTS tenant_id")
