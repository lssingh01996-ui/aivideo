"""Phase 1B Step 6: ProjectMembership + Project unique constraint

Revision ID: a05c3f2b8d1e
Revises: 3f1c9d8a7b2e

Adds:
- uq_project_id_workspace_id on projects (supports ProjectMembership FK)
- project_memberships table (with fk_project_membership_project, uq_project_membership_user_project, ck_project_membership_role)
- User.project_memberships relationship (model-only; table already exists)
- Project.memberships relationship (model-only; new table only)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a05c3f2b8d1e"
down_revision: Union[str, None] = "3f1c9d8a7b2e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add unique constraint on Project(id, workspace_id) required by
    # ProjectMembership composite FK.
    op.create_unique_constraint(
        "uq_project_id_workspace_id",
        "projects",
        ["id", "workspace_id"],
    )

    # Project memberships table: user -> project (same workspace enforced).
    op.create_table(
        "project_memberships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("project_id", sa.String(length=255), nullable=False),
        sa.Column("workspace_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="member"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member')", name="ck_project_membership_role"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["project_id", "workspace_id"],
            ["projects.id", "projects.workspace_id"],
            name="fk_project_membership_project",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "project_id", name="uq_project_membership_user_project"),
    )
    op.create_index("idx_project_membership_user_id", "project_memberships", ["user_id"], unique=False)
    op.create_index("idx_project_membership_project_id", "project_memberships", ["project_id"], unique=False)
    op.create_index("idx_project_membership_workspace_id", "project_memberships", ["workspace_id"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_project_membership_workspace_id", table_name="project_memberships")
    op.drop_index("idx_project_membership_project_id", table_name="project_memberships")
    op.drop_index("idx_project_membership_user_id", table_name="project_memberships")
    op.drop_table("project_memberships")
    op.drop_constraint("uq_project_id_workspace_id", "projects", type_="unique")
