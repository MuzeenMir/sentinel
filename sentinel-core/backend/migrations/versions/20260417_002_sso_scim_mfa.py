"""Add SSO, SCIM token, and MFA challenge persistence tables.

Revision ID: 20260417_002_sso_scim_mfa
Revises: 20260417_001_consolidate_schema
Create Date: 2026-04-17

T-014b adds the Phase 0 schema placeholders for enterprise auth persistence.
The SAML, OIDC, and SCIM token tables model the approved Step-1 schema proposal
for future Phase 1 code wiring. The MFA challenge table captures the current
Redis-backed challenge token shape: token -> user id, 300 second TTL, and
consume-once semantics.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260417_002_sso_scim_mfa"
down_revision: Union[str, None] = "20260417_001_consolidate_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _uuid_pk() -> sa.Column:
    return sa.Column(
        "id",
        postgresql.UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )


def _tenant_fk() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.BigInteger,
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        server_default=sa.text("NOW()"),
        nullable=False,
    )


def _updated_at() -> sa.Column:
    return sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True)


def upgrade() -> None:
    op.create_table(
        "saml_configs",
        _uuid_pk(),
        _tenant_fk(),
        sa.Column("sp_entity_id", sa.Text, nullable=False),
        sa.Column("idp_entity_id", sa.Text, nullable=False),
        sa.Column("idp_sso_url", sa.Text, nullable=False),
        sa.Column("idp_certificate", sa.Text, nullable=False),
        sa.Column("sp_acs_url", sa.Text, nullable=False),
        sa.Column("sp_certificate", sa.Text, nullable=True),
        sa.Column("sp_private_key", sa.Text, nullable=True),
        sa.Column(
            "group_attribute",
            sa.Text,
            server_default=sa.text("'groups'"),
            nullable=False,
        ),
        sa.Column(
            "enabled", sa.Boolean, server_default=sa.text("TRUE"), nullable=False
        ),
        _created_at(),
        _updated_at(),
        sa.UniqueConstraint(
            "tenant_id", "sp_entity_id", name="uq_saml_configs_tenant_sp_entity"
        ),
    )

    op.create_table(
        "oidc_configs",
        _uuid_pk(),
        _tenant_fk(),
        sa.Column("issuer", sa.Text, nullable=False),
        sa.Column("client_id", sa.Text, nullable=False),
        sa.Column("client_secret", sa.Text, nullable=False),
        sa.Column("redirect_uri", sa.Text, nullable=False),
        sa.Column(
            "scopes",
            sa.Text,
            server_default=sa.text("'openid email profile'"),
            nullable=False,
        ),
        sa.Column("discovery_metadata", postgresql.JSONB, nullable=True),
        sa.Column(
            "enabled", sa.Boolean, server_default=sa.text("TRUE"), nullable=False
        ),
        _created_at(),
        _updated_at(),
        sa.UniqueConstraint(
            "tenant_id",
            "issuer",
            "client_id",
            name="uq_oidc_configs_tenant_issuer_client",
        ),
    )

    op.create_table(
        "scim_tokens",
        _uuid_pk(),
        _tenant_fk(),
        sa.Column("token_hash", sa.Text, nullable=False, unique=True),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column(
            "scopes",
            postgresql.JSONB,
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
    )

    op.create_table(
        "mfa_challenges",
        _uuid_pk(),
        _tenant_fk(),
        sa.Column("token", sa.Text, nullable=False),
        sa.Column(
            "user_id",
            sa.BigInteger,
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _updated_at(),
        sa.UniqueConstraint("token", name="uq_mfa_challenges_token"),
    )


def downgrade() -> None:
    op.drop_table("mfa_challenges")
    op.drop_table("scim_tokens")
    op.drop_table("oidc_configs")
    op.drop_table("saml_configs")
