"""Phase 1B Step 1: users, tenant/workspace memberships

Revision ID: 3f1c9d8a7b2e
Revises: 2b55acef440b
Create Date: 2026-09-14

Adds:
- users
- tenant_memberships (with uq_tenant_membership_user_tenant)
- workspace_memberships (with fk_workspace_membership_workspace_belongs_to_tenant
  and fk_workspace_membership_user_tenant)

The new composite FK fk_workspace_membership_user_tenant enforces that
workspace_memberships(user_id, tenant_id) → tenant_memberships(user_id, tenant_id).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "3f1c9d8a7b2e"
down_revision: Union[str, None] = "2b55acef440b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Creation order respects FK dependencies:
    # users (independent) → tenant_memberships (users, tenants) → workspace_memberships
    # (users, tenant_memberships, workspaces).
    # tenants/workspaces already exist from Phase 1A.

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )

    # --- tenant_memberships ---
    op.create_table(
        "tenant_memberships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_tenant_membership_role"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "tenant_id", name="uq_tenant_membership_user_tenant"),
    )
    op.create_index(
        "idx_tenant_membership_user_id",
        "tenant_memberships",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "idx_tenant_membership_tenant_id",
        "tenant_memberships",
        ["tenant_id"],
        unique=False,
    )

    # --- workspace_memberships ---
    op.create_table(
        "workspace_memberships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('admin', 'member')", name="ck_workspace_membership_role"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.id"],
            name="fk_workspace_membership_workspace_belongs_to_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id", "tenant_id"],
            ["tenant_memberships.user_id", "tenant_memberships.tenant_id"],
            name="fk_workspace_membership_user_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "workspace_id", name="uq_workspace_membership_user_workspace"),
    )
    op.create_index(
        "idx_workspace_membership_user_id",
        "workspace_memberships",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "idx_workspace_membership_tenant_id",
        "workspace_memberships",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "idx_workspace_membership_workspace_id",
        "workspace_memberships",
        ["workspace_id"],
        unique=False,
    )


def downgrade() -> None:
    # Reverse creation order: workspace_memberships → tenant_memberships → users
    op.drop_index("idx_workspace_membership_workspace_id", table_name="workspace_memberships")
    op.drop_index("idx_workspace_membership_tenant_id", table_name="workspace_memberships")
    op.drop_index("idx_workspace_membership_user_id", table_name="workspace_memberships")
    op.drop_table("workspace_memberships")

    op.drop_index("idx_tenant_membership_tenant_id", table_name="tenant_memberships")
    op.drop_index("idx_tenant_membership_user_id", table_name="tenant_memberships")
    op.drop_table("tenant_memberships")

    op.drop_table("users")
