"""Widen users.mfa_secret to TEXT for encryption-at-rest (T-027).

The TOTP secret is now stored as an AES-256-GCM envelope (``v1:nonce:ct``) which
is longer than the original 32-char base32 seed, so VARCHAR(32) no longer fits.

Revision ID: 20260530_002_mfa_secret_text
Revises: 20260530_001_reversible_enf
Create Date: 2026-05-30

Chained after the reversible-enforcement migration (PR #49, now on main) to keep
a single linear head.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision: str = "20260530_002_mfa_secret_text"
down_revision: Union[str, None] = "20260530_001_reversible_enf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _mfa_secret_is_text(bind) -> bool:
    for col in inspect(bind).get_columns("users"):
        if col["name"] == "mfa_secret":
            return "TEXT" in str(col["type"]).upper()
    return False


def upgrade() -> None:
    bind = op.get_bind()
    if not _mfa_secret_is_text(bind):
        op.alter_column(
            "users",
            "mfa_secret",
            existing_type=sa.String(length=32),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    # Reverting to VARCHAR(32) will fail if any encrypted (v1:...) secret is
    # present — decrypt + re-store the raw seed before downgrading.
    op.alter_column(
        "users",
        "mfa_secret",
        existing_type=sa.Text(),
        type_=sa.String(length=32),
        existing_nullable=True,
    )
