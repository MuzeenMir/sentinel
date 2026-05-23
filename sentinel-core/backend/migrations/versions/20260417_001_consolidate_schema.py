"""Consolidate current schema state as the Alembic source-of-truth marker.

Revision ID: 20260417_001_consolidate_schema
Revises: 20260313_001
Create Date: 2026-04-17

T-014a implementation choice: (a) placeholder stamp marker.

This revision intentionally performs no schema changes. It records the
consolidation point after the current bootstrap state: `init.sql` plus the
existing `20260304_001_*` and `20260313_001_*` migrations. It must therefore be
a no-op when applied to that state. T-014d will later reduce `init.sql` and move
the full bootstrap DDL into Alembic-managed migrations.

Downgrade is also a no-op: reverting this consolidation marker returns the
database to the prior `20260313_001` schema state without changing objects.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "20260417_001_consolidate_schema"
down_revision: Union[str, None] = "20260313_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Stamp the current schema consolidation point without changing schema."""
    op.execute("SELECT 1")


def downgrade() -> None:
    """No-op downgrade for consolidation point back to 20260313_001."""
    op.execute("SELECT 1")
