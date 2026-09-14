"""SaaS identity and workspace/project SQLAlchemy models.

Phase 1A:
- Tenant
- Workspace
- Project

Phase 1B Step 1:
- User
- TenantMembership
- WorkspaceMembership

Composite foreign keys enforce tenant ownership at the database level.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from lib.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class User(Base):
    """Application user identity.

    Authentication itself is intentionally NOT implemented in this step.
    password_hash is reserved for the future authentication layer.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    tenant_memberships: Mapped[list["TenantMembership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    workspace_memberships: Mapped[list["WorkspaceMembership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    project_memberships: Mapped[list["ProjectMembership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------


class Tenant(Base):
    """Top-level SaaS tenant/account."""

    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    workspaces: Mapped[list["Workspace"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )

    projects: Mapped[list["Project"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )

    memberships: Mapped[list["TenantMembership"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------------------------
# Tenant Membership
# ---------------------------------------------------------------------------


class TenantMembership(Base):
    """Associates a user with a tenant and grants a tenant-level role."""

    __tablename__ = "tenant_memberships"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="member",
        server_default="member",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    user: Mapped["User"] = relationship(
        back_populates="tenant_memberships",
    )

    tenant: Mapped["Tenant"] = relationship(
        back_populates="memberships",
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "tenant_id",
            name="uq_tenant_membership_user_tenant",
        ),
        CheckConstraint(
            "role IN ('owner', 'admin', 'member')",
            name="ck_tenant_membership_role",
        ),
        Index(
            "idx_tenant_membership_user_id",
            "user_id",
        ),
        Index(
            "idx_tenant_membership_tenant_id",
            "tenant_id",
        ),
    )


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


class Workspace(Base):
    """Tenant-owned workspace."""

    __tablename__ = "workspaces"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    storage_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    tenant: Mapped["Tenant"] = relationship(
        back_populates="workspaces",
    )

    projects: Mapped[list["Project"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        overlaps="projects",
    )

    memberships: Mapped[list["WorkspaceMembership"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        overlaps="projects,tenant",
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_workspace_tenant_name",
        ),
        # Referenced column pair for Project and WorkspaceMembership
        # composite FKs must be unique.
        UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_workspace_tenant_id_id",
        ),
        Index(
            "idx_workspace_tenant_id",
            "tenant_id",
        ),
        Index(
            "idx_workspace_storage_path",
            "storage_path",
        ),
    )


# ---------------------------------------------------------------------------
# Workspace Membership
# ---------------------------------------------------------------------------


class WorkspaceMembership(Base):
    """Associates a user with a tenant-owned workspace.

    The composite FK ensures that workspace_id belongs to tenant_id.
    """

    __tablename__ = "workspace_memberships"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
    )

    workspace_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="member",
        server_default="member",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    user: Mapped["User"] = relationship(
        back_populates="workspace_memberships",
    )

    workspace: Mapped["Workspace"] = relationship(
        back_populates="memberships",
        overlaps="projects,tenant",
    )

    __table_args__ = (
        # Workspace must belong to the same tenant recorded by this
        # membership. PostgreSQL enforces this relationship.
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.id"],
            name="fk_workspace_membership_workspace_belongs_to_tenant",
            ondelete="CASCADE",
        ),
        # The user must be a member of the tenant this workspace belongs
        # to. PostgreSQL enforces tenant membership at the database level.
        ForeignKeyConstraint(
            ["user_id", "tenant_id"],
            ["tenant_memberships.user_id", "tenant_memberships.tenant_id"],
            name="fk_workspace_membership_user_tenant",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "user_id",
            "workspace_id",
            name="uq_workspace_membership_user_workspace",
        ),
        CheckConstraint(
            "role IN ('admin', 'member')",
            name="ck_workspace_membership_role",
        ),
        Index(
            "idx_workspace_membership_user_id",
            "user_id",
        ),
        Index(
            "idx_workspace_membership_tenant_id",
            "tenant_id",
        ),
        Index(
            "idx_workspace_membership_workspace_id",
            "workspace_id",
        ),
    )


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------


class Project(Base):
    """Tenant/workspace-owned video project."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(255),
        primary_key=True,
        # Existing codebase convention: string project IDs.
    )

    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )

    workspace_id: Mapped[UUID] = mapped_column(
        # No standalone ForeignKey("workspaces.id") here on purpose.
        # The composite FK below is authoritative and ensures that the
        # workspace belongs to the same tenant as the project.
        PGUUID(as_uuid=True),
        nullable=False,
    )

    slug: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    pipeline_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default="cinematic",
    )

    style_playbook: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default="active",
    )

    storage_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    tenant: Mapped["Tenant"] = relationship(
        back_populates="projects",
        overlaps="projects",
    )

    workspace: Mapped["Workspace"] = relationship(
        back_populates="projects",
        overlaps="projects,tenant",
    )

    memberships: Mapped[list["ProjectMembership"]] = relationship(
        back_populates="project",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        # Project workspace MUST belong to the project's tenant.
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.id"],
            name="fk_project_workspace_belongs_to_tenant",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "slug",
            name="uq_project_tenant_workspace_slug",
        ),
        # Referenced column pair for ProjectMembership composite FK
        # must be unique so PostgreSQL accepts the composite reference.
        UniqueConstraint(
            "id",
            "workspace_id",
            name="uq_project_id_workspace_id",
        ),
        Index(
            "idx_project_tenant_id",
            "tenant_id",
        ),
        Index(
            "idx_project_workspace_id",
            "workspace_id",
        ),
        Index(
            "idx_project_slug",
            "slug",
        ),
        Index(
            "idx_project_status",
            "status",
        ),
    )


# ---------------------------------------------------------------------------
# Project Membership
# ---------------------------------------------------------------------------


class ProjectMembership(Base):
    """Associates a user with a project (same workspace enforced by DB)."""

    __tablename__ = "project_memberships"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    project_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    workspace_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="member",
        server_default="member",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    user: Mapped["User"] = relationship(
        back_populates="project_memberships",
    )

    project: Mapped["Project"] = relationship(
        back_populates="memberships",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "workspace_id"],
            ["projects.id", "projects.workspace_id"],
            name="fk_project_membership_project",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "user_id",
            "project_id",
            name="uq_project_membership_user_project",
        ),
        CheckConstraint(
            "role IN ('owner', 'admin', 'member')",
            name="ck_project_membership_role",
        ),
        Index("idx_project_membership_user_id", "user_id"),
        Index("idx_project_membership_project_id", "project_id"),
        Index("idx_project_membership_workspace_id", "workspace_id"),
    )