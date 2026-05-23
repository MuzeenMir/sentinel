"""Enable tenant RLS policies and prepare an append-only app role.

Revision ID: 20260417_003_enable_rls
Revises: 20260417_002_sso_scim_mfa
Create Date: 2026-04-17

T-014c lands database-side machinery only. Runtime services still connect as
the `sentinel` owner/superuser role until T-028 switches DATABASE_URL and wires
SET LOCAL app.tenant_id.

Grant matrix for sentinel_app:
- audit_log: INSERT, SELECT only. UPDATE, DELETE, TRUNCATE are revoked.
- Tenant-scoped app tables: SELECT, INSERT, UPDATE, DELETE.
- RLS-skip app tables used as global/host/reference data:
  baseline_hashes, ebpf_programs, hardening_posture, host_events,
  token_blacklist: SELECT, INSERT, UPDATE, DELETE.
- model_registry and tenants: SELECT only.
- Sequences: USAGE, SELECT so INSERT works on serial/bigserial tables.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "20260417_003_enable_rls"
down_revision: Union[str, None] = "20260417_002_sso_scim_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


RLS_TABLES: tuple[str, ...] = (
    "audit_log",
    "compliance_assessments",
    "data_retention_policies",
    "hardening_scans",
    "hids_events",
    "integrations",
    "mfa_challenges",
    "oidc_configs",
    "policy_decisions",
    "saml_configs",
    "scim_tokens",
    "users",
    "xai_explanations",
)

OLD_INIT_POLICIES: tuple[tuple[str, str], ...] = (
    ("users", "tenant_isolation_users"),
    ("audit_log", "tenant_isolation_audit"),
    ("policy_decisions", "tenant_isolation_policy"),
    ("compliance_assessments", "tenant_isolation_compliance"),
)

TENANT_DML_TABLES: tuple[str, ...] = (
    "compliance_assessments",
    "data_retention_policies",
    "hardening_scans",
    "hids_events",
    "integrations",
    "mfa_challenges",
    "oidc_configs",
    "policy_decisions",
    "saml_configs",
    "scim_tokens",
    "users",
    "xai_explanations",
)

GLOBAL_DML_TABLES: tuple[str, ...] = (
    "baseline_hashes",
    "ebpf_programs",
    "hardening_posture",
    "host_events",
    "token_blacklist",
)

GLOBAL_READ_TABLES: tuple[str, ...] = (
    "model_registry",
    "tenants",
)


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _policy_name(table: str) -> str:
    return f"rls_{table}_tenant"


def upgrade() -> None:
    for table, policy in OLD_INIT_POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {_q(policy)} ON {_q(table)}")

    for table in RLS_TABLES:
        policy = _policy_name(table)
        op.execute(f"""
            CREATE POLICY {_q(policy)} ON {_q(table)}
              USING (tenant_id = current_setting('app.tenant_id', true)::bigint)
              WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::bigint)
        """)
        op.execute(f"ALTER TABLE {_q(table)} ENABLE ROW LEVEL SECURITY")

    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                CREATE ROLE sentinel_app NOSUPERUSER NOBYPASSRLS NOLOGIN;
            ELSE
                ALTER ROLE sentinel_app NOSUPERUSER NOBYPASSRLS NOLOGIN;
            END IF;
        END
        $$;
    """)

    op.execute("GRANT USAGE ON SCHEMA public TO sentinel_app")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app")

    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM sentinel_app")
    op.execute("GRANT INSERT, SELECT ON audit_log TO sentinel_app")

    for table in TENANT_DML_TABLES + GLOBAL_DML_TABLES:
        op.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {_q(table)} TO sentinel_app"
        )

    for table in GLOBAL_READ_TABLES:
        op.execute(f"GRANT SELECT ON {_q(table)} TO sentinel_app")


def downgrade() -> None:
    op.execute(
        "REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM sentinel_app"
    )

    for table in GLOBAL_READ_TABLES:
        op.execute(f"REVOKE SELECT ON {_q(table)} FROM sentinel_app")

    for table in TENANT_DML_TABLES + GLOBAL_DML_TABLES:
        op.execute(
            f"REVOKE SELECT, INSERT, UPDATE, DELETE ON {_q(table)} FROM sentinel_app"
        )

    op.execute("REVOKE INSERT, SELECT ON audit_log FROM sentinel_app")
    op.execute("REVOKE USAGE ON SCHEMA public FROM sentinel_app")
    op.execute("DROP ROLE IF EXISTS sentinel_app")

    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE {_q(table)} DISABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS {_q(_policy_name(table))} ON {_q(table)}")

    op.execute("""
        CREATE POLICY tenant_isolation_users ON users
            USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT)
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_audit ON audit_log
            USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT)
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON policy_decisions
            USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT)
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_compliance ON compliance_assessments
            USING (tenant_id = current_setting('app.current_tenant_id', TRUE)::BIGINT)
    """)
