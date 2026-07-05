"""Grant read-only node_alerts access to the runtime app role.

The llm-gateway's ``get_node_alerts`` grounding tool reads the local detector
feed directly (single-host, no HTTP hop) and the composed service connects as
``sentinel_app`` (NOSUPERUSER NOBYPASSRLS, T-028). node_alerts was created
owner-only (20260627_001), so the analyst's read failed with permission
denied. SELECT only — the detector (ai-engine) writes via the owner role and
nothing app-facing may mutate alerts.

Revision ID: 20260703_001_node_alerts_grant
Revises: 20260627_001_node_alerts
Create Date: 2026-07-03
"""

from typing import Union

from alembic import op

revision: str = "20260703_001_node_alerts_grant"
down_revision: Union[str, None] = "20260627_001_node_alerts"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                GRANT SELECT ON node_alerts TO sentinel_app;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                REVOKE SELECT ON node_alerts FROM sentinel_app;
            END IF;
        END
        $$;
    """)
