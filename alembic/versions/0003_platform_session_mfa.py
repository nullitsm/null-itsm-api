"""Add mfa_verified to platform_sessions (migration 0003).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-25

The platform refresh flow must preserve the access token's ``mfa``
claim across rotation. The claim is re-derived from the session row
rather than trusted from the presented token: a session created via
the MFA challenge — or via a password login of a user with MFA
disabled (nothing to step up from) — is ``mfa_verified=true``; a
password-only login of an MFA-enabled user never creates a session
at all. The column is additive with a ``false`` default; downgrade
drops it.
"""

from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent: migration 0001's Base.metadata.create_all already
    # creates platform_sessions WITH this column on a fresh install
    # (the ORM model maps it), so a plain add_column would fail with
    # DuplicateColumn there. Add it only when it is missing.
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'platform_sessions' AND column_name = 'mfa_verified'
          ) THEN
            ALTER TABLE platform_sessions
              ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT false;
          END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.drop_column("platform_sessions", "mfa_verified")
