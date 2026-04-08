"""Enterprise schema: tenants, policy decisions, XAI audit, hardening state, data retention.

Adds multi-tenancy foundation (tenants table + tenant_id FK on core tables),
persistent tables for data currently stored in Redis (policy decisions,
XAI explanations, DRL experiences), and data retention support.

Revision ID: 20260313_001
"""

from alembic import op
import sqlalchemy as sa


revision = "20260313_001"
down_revision = "20260304_001"
branch_labels = None
depends_on = None


def upgrade():
    # ── Tenants ──────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("display_name", sa.String(200)),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("plan", sa.String(50), server_default="professional", nullable=False),
        sa.Column("settings", sa.dialects.postgresql.JSONB, server_default="{}"),
        sa.Column("data_region", sa.String(50), server_default="us-east-1"),
        sa.Column("retention_days", sa.Integer, server_default="90"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("status IN ('active', 'suspended', 'deactivated')", name="ck_tenants_status"),
        sa.CheckConstraint("plan IN ('basic', 'professional', 'enterprise')", name="ck_tenants_plan"),
    )

    # Default tenant for single-tenant / migration path
    op.execute("""
        INSERT INTO tenants (name, display_name, plan)
        VALUES ('default', 'Default Organization', 'enterprise')
        ON CONFLICT (name) DO NOTHING
    """)

    # ── Add tenant_id to existing core tables ────────────────────────
    for table in ["alerts", "threats", "firewall_policies", "network_logs",
                  "compliance_assessments", "audit_logs", "training_data",
                  "rl_agent_states", "system_config"]:
        op.add_column(table, sa.Column("tenant_id", sa.BigInteger, nullable=True))
        op.execute(f"""
            UPDATE {table} SET tenant_id = (SELECT id FROM tenants WHERE name = 'default')
            WHERE tenant_id IS NULL
        """)
        op.create_index(f"idx_{table}_tenant_id", table, ["tenant_id"])

    # ── Policy decisions (replace Redis-based DRL decision store) ────
    op.create_table(
        "policy_decisions",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("decision_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
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
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint(
            "action IN ('ALLOW', 'DENY', 'RATE_LIMIT', 'QUARANTINE', 'MONITOR')",
            name="ck_policy_decisions_action",
        ),
    )
    op.create_index("idx_policy_decisions_tenant", "policy_decisions", ["tenant_id"])
    op.create_index("idx_policy_decisions_created", "policy_decisions", [sa.text("created_at DESC")])
    op.create_index("idx_policy_decisions_action", "policy_decisions", ["action"])
    op.create_index("idx_policy_decisions_source", "policy_decisions", ["source_ip"])

    # ── XAI explanations (replace Redis-based audit trail) ───────────
    op.create_table(
        "xai_explanations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("explanation_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("tenant_id", sa.BigInteger, nullable=True),
        sa.Column("detection_id", sa.String(200)),
        sa.Column("decision_id", sa.BigInteger, nullable=True),
        sa.Column("explanation_type", sa.String(30), nullable=False),
        sa.Column("model_name", sa.String(100)),
        sa.Column("feature_importances", sa.dialects.postgresql.JSONB),
        sa.Column("shap_values", sa.dialects.postgresql.JSONB),
        sa.Column("natural_language", sa.Text),
        sa.Column("risk_factors", sa.dialects.postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint(
            "explanation_type IN ('detection', 'policy', 'compliance')",
            name="ck_xai_explanations_type",
        ),
    )
    op.create_index("idx_xai_explanations_tenant", "xai_explanations", ["tenant_id"])
    op.create_index("idx_xai_explanations_detection", "xai_explanations", ["detection_id"])
    op.create_index("idx_xai_explanations_created", "xai_explanations", [sa.text("created_at DESC")])

    # ── Hardening scan results (persistent) ──────────────────────────
    op.create_table(
        "hardening_scans",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("tenant_id", sa.BigInteger, nullable=True),
        sa.Column("hostname", sa.String(255)),
        sa.Column("checks_run", sa.Integer, nullable=False),
        sa.Column("checks_passed", sa.Integer, nullable=False),
        sa.Column("checks_failed", sa.Integer, nullable=False),
        sa.Column("posture_score", sa.Numeric(5, 2)),
        sa.Column("results", sa.dialects.postgresql.JSONB),
        sa.Column("remediations_applied", sa.Integer, server_default="0"),
        sa.Column("scanned_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index("idx_hardening_scans_tenant", "hardening_scans", ["tenant_id"])
    op.create_index("idx_hardening_scans_hostname", "hardening_scans", ["hostname"])
    op.create_index("idx_hardening_scans_scanned", "hardening_scans", [sa.text("scanned_at DESC")])

    # ── HIDS events (persistent, time-series) ────────────────────────
    op.create_table(
        "hids_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("tenant_id", sa.BigInteger, nullable=True),
        sa.Column("hostname", sa.String(255)),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("pid", sa.Integer),
        sa.Column("uid", sa.Integer),
        sa.Column("comm", sa.String(255)),
        sa.Column("filename", sa.String(1024)),
        sa.Column("details", sa.dialects.postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index("idx_hids_events_tenant", "hids_events", ["tenant_id"])
    op.create_index("idx_hids_events_type", "hids_events", ["event_type"])
    op.create_index("idx_hids_events_severity", "hids_events", ["severity"])
    op.create_index("idx_hids_events_created", "hids_events", [sa.text("created_at DESC")])
    op.create_index("idx_hids_events_hostname_time", "hids_events", ["hostname", sa.text("created_at DESC")])

    # ── Integration / webhook registry ───────────────────────────────
    op.create_table(
        "integrations",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("integration_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("tenant_id", sa.BigInteger, nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("config", sa.dialects.postgresql.JSONB, server_default="{}"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True)),
        sa.Column("failure_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint(
            "type IN ('webhook', 'siem_splunk', 'siem_elastic', 'siem_sentinel', "
            "'soar_xsoar', 'soar_tines', 'ticketing_servicenow', 'ticketing_jira', 'email', 'slack', 'custom')",
            name="ck_integrations_type",
        ),
    )
    op.create_index("idx_integrations_tenant", "integrations", ["tenant_id"])
    op.create_index("idx_integrations_type", "integrations", ["type"])

    # ── Model registry (replace file-based model management) ─────────
    op.create_table(
        "model_registry",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("model_id", sa.dialects.postgresql.UUID, server_default=sa.text("gen_random_uuid()"), unique=True, nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("model_type", sa.String(50), nullable=False),
        sa.Column("framework", sa.String(50)),
        sa.Column("artifact_path", sa.String(500)),
        sa.Column("metrics", sa.dialects.postgresql.JSONB),
        sa.Column("parameters", sa.dialects.postgresql.JSONB),
        sa.Column("status", sa.String(20), server_default="staging"),
        sa.Column("promoted_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_model_registry_name_version"),
        sa.CheckConstraint(
            "status IN ('staging', 'production', 'archived', 'failed')",
            name="ck_model_registry_status",
        ),
    )
    op.create_index("idx_model_registry_name", "model_registry", ["name"])
    op.create_index("idx_model_registry_status", "model_registry", ["status"])

    # ── Data retention configuration per tenant ──────────────────────
    op.create_table(
        "data_retention_policies",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.BigInteger, nullable=True),
        sa.Column("table_name", sa.String(100), nullable=False),
        sa.Column("retention_days", sa.Integer, nullable=False),
        sa.Column("archive_to_s3", sa.Boolean, server_default="false"),
        sa.Column("s3_bucket", sa.String(200)),
        sa.Column("last_purged_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.UniqueConstraint("tenant_id", "table_name", name="uq_retention_tenant_table"),
    )

    # ── Insert default retention policies ────────────────────────────
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

    # ── Updated-at trigger for new tables ────────────────────────────
    for table in ["tenants", "integrations"]:
        op.execute(f"""
            CREATE TRIGGER update_{table}_updated_at
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column()
        """)


def downgrade():
    for table in ["data_retention_policies", "model_registry", "integrations",
                  "hids_events", "hardening_scans", "xai_explanations",
                  "policy_decisions", "tenants"]:
        op.drop_table(table)

    for table in ["alerts", "threats", "firewall_policies", "network_logs",
                  "compliance_assessments", "audit_logs", "training_data",
                  "rl_agent_states", "system_config"]:
        op.drop_column(table, "tenant_id")
