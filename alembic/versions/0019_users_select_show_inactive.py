"""Fix users_select RLS: deactivated/suspended members stay visible (0019).

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-26

The original ``users_select`` policy only let a caller read a co-member
when the TARGET membership was ``status = 'active'``:

    ... AND m2.user_id = users.id AND m2.status = 'active'

So the moment a member was suspended or removed (deactivated), their
User row became invisible to the rest of the org and ``list_members``
(which JOINs users) silently dropped them from Organization Users.
Removal is a deactivation, not a delete — the record must stay
visible so an admin can see the Deactivated row and verify the
removal. The fix drops the target-status condition; the caller's
membership must still be active (``m1.status = 'active'``), so a
removed user still cannot read anyone else.
"""

from __future__ import annotations

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

NEW_USING = (
    "id::text = current_setting('app.current_user_id', true) OR EXISTS ("
    "SELECT 1 FROM memberships m1 JOIN memberships m2 ON m1.organization_id = m2.organization_id "
    "WHERE m1.user_id::text = current_setting('app.current_user_id', true) AND m1.status = 'active' "
    "AND m2.user_id = users.id)"
)


def upgrade() -> None:
    op.execute("DROP POLICY IF EXISTS users_select ON users")
    op.execute(f"CREATE POLICY users_select ON users FOR SELECT USING ({NEW_USING})")


def downgrade() -> None:
    old_using = (
        "id::text = current_setting('app.current_user_id', true) OR EXISTS ("
        "SELECT 1 FROM memberships m1 JOIN memberships m2 ON m1.organization_id = m2.organization_id "
        "WHERE m1.user_id::text = current_setting('app.current_user_id', true) AND m1.status = 'active' "
        "AND m2.user_id = users.id AND m2.status = 'active')"
    )
    op.execute("DROP POLICY IF EXISTS users_select ON users")
    op.execute(f"CREATE POLICY users_select ON users FOR SELECT USING ({old_using})")
