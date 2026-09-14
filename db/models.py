"""Phase 1A SQLAlchemy models: tenants, workspaces, projects.

Composite FK (tenant_id, workspace_id) -> workspaces(tenant_id, id) enforces
at the DB level that a project's workspace belongs to the project's tenant.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4, UUID

from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from lib.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    workspaces: Mapped[list["Workspace"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    projects: Mapped[list["Project"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="workspaces")
    projects: Mapped[list["Project"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        overlaps="projects",
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_workspace_tenant_name"),
        # Referenced column pair for Project's composite FK must be unique.
        UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_workspace_tenant_id_id",
        ),
        Index("idx_workspace_tenant_id", "tenant_id"),
        Index("idx_workspace_storage_path", "storage_path"),
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(255), primary_key=True  # existing codebase convention: str IDs
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    workspace_id: Mapped[UUID] = mapped_column(
        # No standalone ForeignKey("workspaces.id") here on purpose: the
        # composite (tenant_id, workspace_id) -> workspaces(tenant_id, id)
        # constraint below is the authoritative FK. It alone enforces that the
        # project's workspace belongs to the project's tenant (Phase 1A
        # integrity requirement). PostgreSQL rejects the row otherwise.
        PGUUID(as_uuid=True),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    pipeline_type: Mapped[str] = mapped_column(
        String(100), nullable=False, server_default="cinematic"
    )
    style_playbook: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, server_default="active"
    )
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    tenant: Mapped["Tenant"] = relationship(
        back_populates="projects", overlaps="projects"
    )
    workspace: Mapped["Workspace"] = relationship(
        back_populates="projects", overlaps="projects,tenant"
    )

    __table_args__ = (
        # Composite FK: project's workspace MUST belong to the project's tenant.
        # Enforced in PostgreSQL, not app code.
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.id"],
            name="fk_project_workspace_belongs_to_tenant",
            ondelete="CASCADE",
        ),
        # slug unique within tenant/workspace scope
        UniqueConstraint(
            "tenant_id",
            "workspace_id",
            "slug",
            name="uq_project_tenant_workspace_slug",
        ),
        Index("idx_project_tenant_id", "tenant_id"),
        Index("idx_project_workspace_id", "workspace_id"),
        Index("idx_project_slug", "slug"),
        Index("idx_project_status", "status"),
    )