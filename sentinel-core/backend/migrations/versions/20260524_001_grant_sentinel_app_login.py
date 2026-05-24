"""Promote sentinel_app to LOGIN role and set its password from env (T-028).

Revision ID: 20260524_001_grant_sentinel_app_login
Revises: 20260417_003_enable_rls
Create Date: 2026-05-24

T-014c (20260417_003_enable_rls) created the `sentinel_app` role as
`NOSUPERUSER NOBYPASSRLS NOLOGIN` and installed the grant/REVOKE matrix.
T-028 wires the runtime application to connect as `sentinel_app` instead of
the migration superuser `sentinel`. To make that possible, `sentinel_app`
needs LOGIN + a password.

Migrations continue to run as `sentinel` (table owner, BYPASSRLS). This
migration runs at the tail of the migration sequence as the same superuser,
so it has authority to ALTER the role.

Password source: ``SENTINEL_APP_DB_PASSWORD`` environment variable. The
migration fails-fast if unset, since shipping a `sentinel_app` role without a
password and then handing the runtime DSN a placeholder would let the app
silently fall back to no-auth. The CI workflows and compose/Helm wiring all
populate the var from a Secret/`.env`.

The password is interpolated using a PostgreSQL dollar-quoted string literal
with a collision-checked tag. This avoids both SQL injection (no app-supplied
chars reach an unquoted position) and the DDL-parameter-binding limitation
(PostgreSQL does not accept bound parameters for ALTER ROLE ... PASSWORD).
"""

import os
import secrets
from typing import Sequence, Union

from alembic import op


revision: str = "20260524_001_grant_sentinel_app_login"
down_revision: Union[str, None] = "20260417_003_enable_rls"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dollar_quote(value: str) -> str:
    """Wrap ``value`` in a PostgreSQL dollar-quoted string with a tag that is
    guaranteed not to appear inside ``value``. Used for DDL where parameter
    binding is not available (e.g. ``ALTER ROLE ... PASSWORD``)."""
    tag = "pw"
    while f"${tag}$" in value:
        tag = "pw" + secrets.token_hex(4)
    return f"${tag}${value}${tag}$"


def upgrade() -> None:
    pwd = os.environ.get("SENTINEL_APP_DB_PASSWORD")
    if not pwd:
        raise RuntimeError(
            "SENTINEL_APP_DB_PASSWORD is required for the T-028 runtime role "
            "provisioning. Set it in the migration environment (db-migrate "
            "service env, CI workflow env, or Helm Secret) before running "
            "`alembic upgrade head`."
        )

    quoted_pwd = _dollar_quote(pwd)
    op.execute(
        f"ALTER ROLE sentinel_app WITH LOGIN PASSWORD {quoted_pwd}"
    )


def downgrade() -> None:
    op.execute("ALTER ROLE sentinel_app WITH NOLOGIN PASSWORD NULL")
