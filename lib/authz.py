"""Phase 1B Step 9: authorization / RBAC.

Builds on the membership models in ``db.models`` and authenticated-user
identity from ``lib.auth_session``. Provides the pure role logic plus the
FastAPI dependency that guards project-scoped routes (currently
``/api/project/{project_id}/state``).

Rules (single source of truth):
- Tenants:    owner > admin > member
- Workspaces: admin > member
- Projects:   owner > admin > member
- A role at one level does NOT imply a role at another level.
- Unknown/empty roles fail closed (deny).
- Unauthenticated => 401; authenticated but unauthorized => 403.
- No 404 anti-enumeration in Step 9.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, Path, Request
from sqlalchemy import select

TENANT_ROLES = ("owner", "admin", "member")
WORKSPACE_ROLES = ("admin", "member")
PROJECT_ROLES = ("owner", "admin", "member")

_ROLE_RANK = {
    "owner": 3,
    "admin": 2,
    "member": 1,
}


def role_rank(role: str) -> int:
    """Return the rank of a role for ordering; unknown/empty -> 0 (fail closed)."""
    return _ROLE_RANK.get(role, 0)


def granted(required: str, actual: str) -> bool:
    """True iff ``actual`` satisfies ``required``. Unknown roles fail closed."""
    if required not in _ROLE_RANK or actual not in _ROLE_RANK:
        return False
    return _ROLE_RANK[actual] >= _ROLE_RANK[required]


# ---------------------------------------------------------------------------
# Membership resolvers (Postgres via lib.db.SessionFactory; sessions closed)
# ---------------------------------------------------------------------------


def get_tenant_role(user_id, tenant_id) -> str | None:
    """Return the user's tenant-level role, or None if no membership exists."""
    from lib.db import SessionFactory
    from db.models import TenantMembership

    uid = uuid.UUID(str(user_id))
    tid = uuid.UUID(str(tenant_id))
    db = SessionFactory()
    try:
        m = db.scalar(
            select(TenantMembership).where(
                TenantMembership.user_id == uid,
                TenantMembership.tenant_id == tid,
            )
        )
        return m.role if m is not None else None
    finally:
        db.close()


def get_workspace_role(user_id, workspace_id) -> str | None:
    """Return the user's workspace-level role, or None (no implicit tenant grant)."""
    from lib.db import SessionFactory
    from db.models import WorkspaceMembership

    uid = uuid.UUID(str(user_id))
    wid = uuid.UUID(str(workspace_id))
    db = SessionFactory()
    try:
        m = db.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.user_id == uid,
                WorkspaceMembership.workspace_id == wid,
            )
        )
        return m.role if m is not None else None
    finally:
        db.close()


def get_project_role(user_id, project_id) -> str | None:
    """Return the user's project-level role, or None (no implicit workspace grant)."""
    from lib.db import SessionFactory
    from db.models import ProjectMembership

    uid = uuid.UUID(str(user_id))
    db = SessionFactory()
    try:
        m = db.scalar(
            select(ProjectMembership).where(
                ProjectMembership.user_id == uid,
                ProjectMembership.project_id == project_id,
            )
        )
        return m.role if m is not None else None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Decisional API
# ---------------------------------------------------------------------------


def require_scope(
    user_id,
    *,
    tenant=None,
    workspace=None,
    project=None,
    tenant_role=None,
    workspace_role=None,
    project_role=None,
) -> str | None:
    """Return None if allowed, else a 403 reason string.

    Each checked level must have an explicit membership with a sufficient
    role. No implicit cross-level grants.
    """
    if tenant is not None and tenant_role is not None:
        actual = get_tenant_role(user_id, tenant)
        if actual is None or not granted(tenant_role, actual):
            return "Missing or insufficient tenant role."

    if workspace is not None and workspace_role is not None:
        actual = get_workspace_role(user_id, workspace)
        if actual is None or not granted(workspace_role, actual):
            return "Missing or insufficient workspace role."

    if project is not None and project_role is not None:
        actual = get_project_role(user_id, project)
        if actual is None or not granted(project_role, actual):
            return "Missing or insufficient project role."

    return None


# ---------------------------------------------------------------------------
# FastAPI dependency for project-scoped routes
# ---------------------------------------------------------------------------


def require_project_member(request: Request, project_id: str = Path(...)) -> None:
    """Dependency: enforce full RBAC chain; 401 when unauthenticated/inactive; 403 when unauthorized."""
    from lib.auth_session import get_current_user
    from lib.db import SessionFactory
    from db.models import Project

    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Chain: project must exist; must belong to workspace; workspace to tenant.
    # User must have explicit membership at all three levels (no implicit grants).
    db = SessionFactory()
    try:
        proj = db.get(Project, project_id)
        if proj is None:
            raise HTTPException(status_code=403, detail="Project access denied.")

        # Explicit project membership (no implicit workspace/tenant grant)
        proj_role = get_project_role(user.id, project_id)
        if proj_role is None or not granted("member", proj_role):
            raise HTTPException(status_code=403, detail="Missing or insufficient project role.")

        # Explicit workspace membership for this workspace
        ws_role = get_workspace_role(user.id, proj.workspace_id)
        if ws_role is None or not granted("member", ws_role):
            raise HTTPException(status_code=403, detail="Missing or insufficient workspace role.")

        # Explicit tenant membership for this tenant
        tenant_role = get_tenant_role(user.id, proj.tenant_id)
        if tenant_role is None or not granted("member", tenant_role):
            raise HTTPException(status_code=403, detail="Missing or insufficient tenant role.")
    finally:
        db.close()