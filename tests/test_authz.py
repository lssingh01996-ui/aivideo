"""Phase 1B Step 9: authorization / RBAC unit + dependency tests.

Mirrors ``tests/test_auth_session.py``: isolates to the ``vid01_test``
Postgres database, creates schema idempotently, and exercises the real
SessionFactory-backed resolvers. No in-memory database.
"""

import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

# Isolate to vid01_test before importing lib.db/models.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")
_RAW = os.environ.get("DATABASE_URL", "")
if _RAW:
    _p = urlsplit(_RAW)
    os.environ["DATABASE_URL"] = urlunsplit(
        (_p.scheme, _p.netloc, "/vid01_test", _p.query, _p.fragment)
    )

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from db.models import (  # noqa: E402
    Project,
    ProjectMembership,
    Tenant,
    TenantMembership,
    User,
    Workspace,
    WorkspaceMembership,
)
from lib.authz import granted, require_scope, role_rank  # noqa: E402
from lib.db import Base, engine  # noqa: E402

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="module", autouse=True)
def _authz_tables():
    Base.metadata.create_all(bind=engine)
    yield
    # Do not drop — module-scoped tables shared with other Phase 1B tests.


@pytest.fixture
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Row helpers
# ---------------------------------------------------------------------------


def _user(db, *, is_active=True):
    u = User(
        id=uuid.uuid4(),
        email=f"t{uuid.uuid4().hex[:10]}@ex.com",
        password_hash="authz-test-hash",
        is_active=is_active,
    )
    db.add(u)
    db.commit()
    return u


def _tenant(db):
    t = Tenant(id=uuid.uuid4(), name=f"tenant{uuid.uuid4().hex[:10]}")
    db.add(t)
    db.commit()
    return t


def _tenant_membership(db, user, tenant, role):
    m = TenantMembership(
        id=uuid.uuid4(), user_id=user.id, tenant_id=tenant.id, role=role
    )
    db.add(m)
    db.commit()
    return m


def _workspace(db, tenant):
    w = Workspace(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        name=f"ws{uuid.uuid4().hex[:10]}",
        storage_path=f"/tmp/{uuid.uuid4().hex}",
    )
    db.add(w)
    db.commit()
    return w


def _workspace_membership(db, user, tenant, workspace, role):
    m = WorkspaceMembership(
        id=uuid.uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        workspace_id=workspace.id,
        role=role,
    )
    db.add(m)
    db.commit()
    return m


def _project(db, tenant, workspace):
    p = Project(
        id=uuid.uuid4().hex[:12],
        tenant_id=tenant.id,
        workspace_id=workspace.id,
        slug=f"proj{uuid.uuid4().hex[:8]}",
        title="authz test project",
        pipeline_type="cinematic",
        status="active",
        storage_path=f"/tmp/{uuid.uuid4().hex}",
    )
    db.add(p)
    db.commit()
    return p


def _project_membership(db, user, project, workspace, role):
    m = ProjectMembership(
        id=uuid.uuid4(),
        user_id=user.id,
        project_id=project.id,
        workspace_id=workspace.id,
        role=role,
    )
    db.add(m)
    db.commit()
    return m


# ---------------------------------------------------------------------------
# Role hierarchy + fail-closed (pure, no DB)
# ---------------------------------------------------------------------------


def test_role_rank_hierarchy():
    assert role_rank("owner") == 3
    assert role_rank("admin") == 2
    assert role_rank("member") == 1


def test_role_rank_unknown_fails_closed_to_zero():
    assert role_rank("superuser") == 0
    assert role_rank("") == 0


def test_granted_tenant_hierarchy():
    assert granted("member", "member")
    assert granted("member", "admin")
    assert granted("member", "owner")
    assert not granted("admin", "member")
    assert granted("admin", "admin")
    assert granted("admin", "owner")
    assert not granted("owner", "member")
    assert not granted("owner", "admin")
    assert granted("owner", "owner")


def test_granted_workspace_hierarchy():
    assert granted("member", "member")
    assert granted("member", "admin")
    assert granted("admin", "admin")
    assert not granted("admin", "member")


def test_granted_unknown_roles_fail_closed():
    assert not granted("member", "superuser")
    assert not granted("superuser", "member")
    assert not granted("member", "")
    assert not granted("", "member")


# ---------------------------------------------------------------------------
# Resolvers (Postgres-backed)
# ---------------------------------------------------------------------------


def test_get_tenant_role_returns_role(db):
    from lib.authz import get_tenant_role

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "owner")
    assert get_tenant_role(u.id, t.id) == "owner"


def test_get_tenant_role_none_when_absent(db):
    from lib.authz import get_tenant_role

    u = _user(db)
    t = _tenant(db)
    assert get_tenant_role(u.id, t.id) is None


def test_get_workspace_role_returns_role(db):
    from lib.authz import get_workspace_role

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "admin")
    assert get_workspace_role(u.id, w.id) == "admin"


def test_tenant_member_does_not_grant_workspace_access(db):
    from lib.authz import get_workspace_role

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "owner")  # tenant owner, but no workspace membership
    w = _workspace(db, t)
    assert get_workspace_role(u.id, w.id) is None


def test_get_project_role_returns_role(db):
    from lib.authz import get_project_role

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "member")
    p = _project(db, t, w)
    _project_membership(db, u, p, w, "member")
    assert get_project_role(u.id, p.id) == "member"


def test_workspace_admin_does_not_grant_project_access(db):
    from lib.authz import get_project_role

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "admin")  # workspace admin, no project membership
    p = _project(db, t, w)
    assert get_project_role(u.id, p.id) is None


def test_cross_tenant_denied(db):
    from lib.authz import get_project_role

    u = _user(db)
    t1 = _tenant(db)
    t2 = _tenant(db)
    _tenant_membership(db, u, t1, "owner")
    w2 = _workspace(db, t2)
    p2 = _project(db, t2, w2)
    assert get_project_role(u.id, p2.id) is None


# ---------------------------------------------------------------------------
# require_scope decisional API
# ---------------------------------------------------------------------------


def test_require_scope_allows_matching_project_member(db):
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "member")
    p = _project(db, t, w)
    _project_membership(db, u, p, w, "member")
    assert require_scope(u.id, project=p.id, project_role="member") is None


def test_require_scope_denies_insufficient_project_role(db):
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "member")
    p = _project(db, t, w)
    _project_membership(db, u, p, w, "member")  # member cannot satisfy admin
    assert require_scope(u.id, project=p.id, project_role="admin") is not None


def test_require_scope_denies_missing_project_role(db):
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "admin")
    p = _project(db, t, w)
    assert require_scope(u.id, project=p.id, project_role="member") is not None


def test_require_scope_workspace_does_not_imply_project(db):
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "admin")
    p = _project(db, t, w)
    assert require_scope(u.id, project=p.id, project_role="member") is not None


# ---------------------------------------------------------------------------
# require_project_member FastAPI dependency (401 / 403 / allowed)
# ---------------------------------------------------------------------------


class DummyRequest:
    def __init__(self, session):
        self.session = session


def test_dependency_unauthenticated_401():
    from lib.authz import require_project_member

    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({}), project_id="does-not-exist")
    assert ei.value.status_code == 401


def test_dependency_inactive_user_401(db):
    from lib.authz import require_project_member

    u = _user(db, is_active=False)
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id="x")
    assert ei.value.status_code == 401


def test_dependency_nonmember_403(db):
    from lib.authz import require_project_member

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    p = _project(db, t, w)  # no project membership for u
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p.id)
    assert ei.value.status_code == 403


def test_dependency_cross_tenant_403(db):
    from lib.authz import require_project_member

    u = _user(db)
    t1 = _tenant(db)
    t2 = _tenant(db)
    _tenant_membership(db, u, t1, "owner")
    w2 = _workspace(db, t2)
    p2 = _project(db, t2, w2)
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p2.id)
    assert ei.value.status_code == 403


def test_dependency_authorized_member_passes(db):
    from lib.authz import require_project_member

    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "member")
    p = _project(db, t, w)
    _project_membership(db, u, p, w, "member")
    assert (
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p.id)
        is None
    )

# =====================================================================
# Required Step 9 proof tests ( RBAC chain / no implicit grants )
# =====================================================================

def test_1_tenant_a_cannot_access_tenant_b_project(db):
    """Cross-tenant: membership in Tenant A, project in Tenant B => 403."""
    from lib.authz import require_project_member
    u = _user(db)
    t_a = _tenant(db); t_b = _tenant(db)
    _tenant_membership(db, u, t_a, "owner")
    w_b = _workspace(db, t_b); p_b = _project(db, t_b, w_b)
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p_b.id)
    assert ei.value.status_code == 403

def test_2_tenant_a_plus_workspace_a_cannot_access_tenant_b_project(db):
    """Cross-tenant with workspace membership: still denied for Tenant B project."""
    from lib.authz import require_project_member
    u = _user(db)
    t_a = _tenant(db); t_b = _tenant(db)
    _tenant_membership(db, u, t_a, "owner")
    w_a = _workspace(db, t_a); _workspace_membership(db, u, t_a, w_a, "admin")
    w_b = _workspace(db, t_b); p_b = _project(db, t_b, w_b)
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p_b.id)
    assert ei.value.status_code == 403

def test_3_project_membership_on_tenant_b_project_without_tenant_b_membership_denied(db):
    """Direct ProjectMembership but missing tenant membership => denied."""
    from lib.authz import require_project_member
    u = _user(db)
    t_b = _tenant(db)
    w_b = _workspace(db, t_b)
    p_b = _project(db, t_b, w_b)
    # Direct project membership WITHOUT tenant membership
    _project_membership(db, u, p_b, w_b, "member")
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p_b.id)
    assert ei.value.status_code == 403

def test_4_workspace_admin_without_project_membership_denied(db):
    """Workspace admin has workspace role but no ProjectMembership => denied."""
    from lib.authz import require_project_member
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "admin")
    p = _project(db, t, w)
    # No _project_membership call => should deny
    with pytest.raises(HTTPException) as ei:
        require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p.id)
    assert ei.value.status_code == 403

def test_5_authorized_project_member_succeeds(db):
    """Full chain satisfied => passes (returns None, no exception)."""
    from lib.authz import require_project_member
    u = _user(db)
    t = _tenant(db)
    _tenant_membership(db, u, t, "member")
    w = _workspace(db, t)
    _workspace_membership(db, u, t, w, "member")
    p = _project(db, t, w)
    _project_membership(db, u, p, w, "member")
    result = require_project_member(DummyRequest({"user_id": str(u.id)}), project_id=p.id)
    assert result is None
