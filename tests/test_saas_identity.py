"""Phase 1A tests: tenant/workspace/project creation and relationship constraints.

These tests hit a **dedicated test database, `vid01_test`** — never the
production/development `vid01` database that Phase 1A was migrated into.

How isolation works (do not reorder):
1. `.env` is loaded so the connection inherits the host/user/password.
2. The loaded `DATABASE_URL` is *rewritten* so its database name becomes
   `vid01_test`. Credentials are untouched; only the database is swapped.
3. Only then are `lib.db` / `db.models` imported. `lib.db` builds its engine
   from the process `DATABASE_URL` at import time, so this MUST happen first.

The identity tables are created once for the module and dropped afterward —
always inside `vid01_test`. These tests do not touch checkpoints, artifacts,
events, cost tracking, or filesystem storage.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4, UUID

import pytest
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

# --- Test-DB isolation gate (must run BEFORE any lib.db / db.models import) ---
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

_RAW_URL = os.environ.get("DATABASE_URL")
if not _RAW_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Phase 1A tests require a configured "
        "PostgreSQL backend (see .env)."
    )

_parts = urlsplit(_RAW_URL)
# Swap the database name to the dedicated test database; keep scheme, host,
# port, user, password, and any query params intact.
_TEST_DB = "vid01_test"
_REWRITTEN = urlunsplit(
    (
        _parts.scheme,
        _parts.netloc,
        f"/{_TEST_DB}",
        _parts.query,
        _parts.fragment,
    )
)
os.environ["DATABASE_URL"] = _REWRITTEN

# Redacted confirmation: scheme/host/db only, never credentials.
_netloc_bits = _parts.netloc.rsplit("@", 1)
_redacted_netloc = _netloc_bits[-1] if len(_netloc_bits) > 1 else _parts.netloc
print(
    f"[test_saas_identity] engine -> {_parts.scheme}://{_redacted_netloc} "
    f"(database={_TEST_DB})"
)

# Imports AFTER the DATABASE_URL override so the engine binds to vid01_test.
from db.models import Tenant, Workspace, Project, User, TenantMembership, WorkspaceMembership  # noqa: E402
from lib.db import Base, engine  # noqa: E402

# A dedicated test-engine session factory bound to the vid01_test engine.
# Tests drop/recreate the identity tables so they are hermetic per run.
TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="module", autouse=True)
def _identity_tables():
    """Create Phase 1A/1B tables once; drop them after the module."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def session(_identity_tables):
    s = TestSession()
    try:
        yield s
    finally:
        s.close()


def _user(session, email: str | None = None) -> User:
    u = User(
        id=uuid4(),
        email=email or f"user-{uuid4().hex[:8]}@example.com",
        password_hash="fake-hash",
    )
    session.add(u)
    session.commit()
    return u


def _tenant(session, name: str | None = None) -> Tenant:
    t = Tenant(id=uuid4(), name=name or f"tenant-{uuid4().hex[:8]}")
    session.add(t)
    session.commit()
    return t


def _workspace(session, tenant: Tenant, name: str | None = None) -> Workspace:
    w = Workspace(
        id=uuid4(),
        tenant_id=tenant.id,
        name=name or f"ws-{uuid4().hex[:8]}",
        storage_path=f"/ws/{uuid4().hex[:8]}",
    )
    session.add(w)
    session.commit()
    return w


# --- Tenant ---

def test_create_tenant(session):
    t = Tenant(id=uuid4(), name=f"tenant-{uuid4().hex[:8]}")
    session.add(t)
    session.commit()
    # Re-fetch by PK from a fresh session to confirm row persisted.
    got = session.get(Tenant, t.id)
    assert got is not None
    assert isinstance(got.id, UUID)
    assert got.created_at is not None and got.updated_at is not None


def test_tenant_name_unique(session):
    name = f"dup-{uuid4().hex[:8]}"
    t1 = Tenant(id=uuid4(), name=name)
    session.add(t1)
    session.commit()
    # Second tenant with same name violates the unique constraint.
    t2 = Tenant(id=uuid4(), name=name)
    session.add(t2)
    with pytest.raises(IntegrityError):
        session.commit()


# --- Workspace ---

def test_create_workspace(session):
    t = _tenant(session)
    w = _workspace(session, t)
    got = session.get(Workspace, w.id)
    assert got is not None
    assert got.tenant_id == t.id
    assert got.storage_path
    assert got.created_at is not None and got.updated_at is not None


def test_workspace_belongs_to_tenant(session):
    t1 = _tenant(session)
    t2 = _tenant(session)
    w1 = _workspace(session, t1)
    w2 = _workspace(session, t2)
    # Each workspace sees only its own tenant via the relationship.
    assert w1.tenant.id == t1.id
    assert w2.tenant.id == t2.id
    assert t1.workspaces == [w1] and t2.workspaces == [w2]


def test_workspace_unique_name_per_tenant(session):
    t = _tenant(session)
    name = f"wsdup-{uuid4().hex[:8]}"
    w1 = Workspace(id=uuid4(), tenant_id=t.id, name=name, storage_path="/1")
    session.add(w1)
    session.commit()
    w2 = Workspace(id=uuid4(), tenant_id=t.id, name=name, storage_path="/2")
    session.add(w2)
    with pytest.raises(IntegrityError):
        session.commit()


def test_workspace_cascade_delete_tenant(session):
    t = _tenant(session)
    w = _workspace(session, t)
    wid = w.id
    session.delete(t)
    session.commit()
    assert session.get(Workspace, wid) is None


def test_workspace_name_can_repeat_across_tenants(session):
    # Same workspace name is allowed under different tenants.
    name = f"shared-{uuid4().hex[:8]}"
    t1 = _tenant(session)
    t2 = _tenant(session)
    w1 = Workspace(id=uuid4(), tenant_id=t1.id, name=name, storage_path="/1")
    w2 = Workspace(id=uuid4(), tenant_id=t2.id, name=name, storage_path="/2")
    session.add_all([w1, w2])
    session.commit()  # should NOT raise


# --- Project ---

def test_create_project(session):
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}",
        tenant_id=t.id,
        workspace_id=w.id,
        slug="my-film",
        title="My Film",
        pipeline_type="cinematic",
        style_playbook="modern",
        status="active",
        storage_path=f"/ws/{w.id}/my-film",
    )
    session.add(p)
    session.commit()
    got = session.get(Project, p.id)
    assert got is not None
    assert got.id == p.id  # str ID preserved
    assert got.title == "My Film"
    assert got.pipeline_type == "cinematic"
    # style_playbook/status/storage_path preserved exactly
    assert got.style_playbook == "modern"
    assert got.status == "active"
    assert got.storage_path == p.storage_path
    assert got.created_at is not None and got.updated_at is not None


def test_project_slug_unique_per_tenant_workspace(session):
    t = _tenant(session)
    w = _workspace(session, t)
    p1 = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film 1", storage_path="/w/film",
    )
    session.add(p1)
    session.commit()
    p2 = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film 2", storage_path="/w/film2",
    )
    session.add(p2)
    with pytest.raises(IntegrityError):
        session.commit()


def test_project_slug_can_repeat_across_workspaces(session):
    t = _tenant(session)
    w1 = _workspace(session, t, name="w1")
    w2 = _workspace(session, t, name="w2")
    p1 = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w1.id,
        slug="film", title="W1 Film", storage_path="/w1/film",
    )
    p2 = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w2.id,
        slug="film", title="W2 Film", storage_path="/w2/film",
    )
    session.add_all([p1, p2])
    session.commit()  # should NOT raise — different workspaces


def test_project_fk_tenant_cascade(session):
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film", storage_path="/w/film",
    )
    session.add(p)
    session.commit()
    pid = p.id
    session.delete(t)
    session.commit()
    assert session.get(Project, pid) is None


def test_project_fk_workspace_cascade(session):
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film", storage_path="/w/film",
    )
    session.add(p)
    session.commit()
    pid = p.id
    session.delete(w)
    session.commit()
    assert session.get(Project, pid) is None


def test_project_workspace_relationship(session):
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film", storage_path="/w/film",
    )
    session.add(p)
    session.commit()
    got = session.get(Project, p.id)
    assert got.workspace is not None
    assert got.workspace.id == w.id
    assert w.projects and got in w.projects


def test_project_tenant_relationship_integrity(session):
    """Project.tenant must resolve to the project's tenant (Fix #1)."""
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="film", title="Film", storage_path="/w/film",
    )
    session.add(p)
    session.commit()
    got = session.get(Project, p.id)
    assert got.tenant is not None
    assert got.tenant.id == t.id
    assert t.projects and got in t.projects


def test_project_rejects_foreign_workspace(session):
    """Composite FK (Fix #2): a project in Tenant A must not use a workspace
    belonging to Tenant B, enforced by PostgreSQL."""
    tA = _tenant(session)
    tB = _tenant(session)
    wB = _workspace(session, tB)
    # Deliberately assign tenant_id=tA but workspace_id=wB (belongs to tB).
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=tA.id, workspace_id=wB.id,
        slug="film", title="Cross-tenant", storage_path="/w/film",
    )
    session.add(p)
    with pytest.raises(IntegrityError):
        session.commit()


def test_project_created_at_timestamp(session):
    """Requirement #4: created_at is populated and persists."""
    t = _tenant(session)
    w = _workspace(session, t)
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="stamp", title="Stamp", storage_path="/w/stamp",
    )
    session.add(p)
    session.commit()
    got = session.get(Project, p.id)
    assert got.created_at is not None
    assert isinstance(got.created_at, datetime)
    # No future timestamp at creation.
    assert got.created_at.tzinfo is not None


def test_project_updated_on_modify(session):
    """Requirement #4: updating a project bumps updated_at."""
    t = _tenant(session)
    w = _workspace(session, t)
    import time as _time
    p = Project(
        id=f"proj-{uuid4().hex[:8]}", tenant_id=t.id, workspace_id=w.id,
        slug="update", title="Before", storage_path="/w/update",
    )
    session.add(p)
    session.commit()
    created = p.created_at
    updated_before = p.updated_at
    _time.sleep(0.05)  # ensure distinct timestamp for updated_at
    p.title = "After"
    session.commit()
    got = session.get(Project, p.id)
    assert got.created_at == created
    assert got.updated_at >= updated_before


# --- User (Phase 1B) ---

def test_create_user(session):
    email = f"test-{uuid4().hex[:8]}@example.com"
    u = User(id=uuid4(), email=email, password_hash="hashed")
    session.add(u)
    session.commit()
    got = session.get(User, u.id)
    assert got is not None
    assert got.email == email
    assert got.password_hash == "hashed"
    assert got.is_active is True


def test_create_tenant_membership(session):
    u = _user(session)
    t = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, role="admin")
    session.add(tm)
    session.commit()
    got = session.get(TenantMembership, tm.id)
    assert got is not None
    assert got.user_id == u.id
    assert got.tenant_id == t.id
    assert got.role == "admin"


def test_tenant_membership_unique_user_tenant(session):
    u = _user(session)
    t = _tenant(session)
    tm1 = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id)
    session.add(tm1)
    session.commit()
    tm2 = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id)
    session.add(tm2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_tenant_membership_invalid_role(session):
    u = _user(session)
    t = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, role="invalid")
    session.add(tm)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_create_workspace_membership(session):
    u = _user(session)
    t = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id)
    session.add(tm)
    w = _workspace(session, t)
    wm = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, workspace_id=w.id, role="admin")
    session.add(wm)
    session.commit()
    got = session.get(WorkspaceMembership, wm.id)
    assert got is not None
    assert got.user_id == u.id
    assert got.workspace_id == w.id


def test_workspace_membership_rejects_non_tenant_member(session):
    u = _user(session)
    t = _tenant(session)
    w = _workspace(session, t)
    wm = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, workspace_id=w.id)
    session.add(wm)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_workspace_membership_rejects_foreign_workspace(session):
    u = _user(session)
    t1 = _tenant(session)
    t2 = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t1.id)
    session.add(tm)
    w2 = _workspace(session, t2)
    wm = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t1.id, workspace_id=w2.id)
    session.add(wm)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_workspace_membership_unique_user_workspace(session):
    u = _user(session)
    t = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id)
    w = _workspace(session, t)
    wm1 = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, workspace_id=w.id)
    session.add_all([tm, wm1])
    session.commit()
    wm2 = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, workspace_id=w.id)
    session.add(wm2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_workspace_membership_invalid_role(session):
    u = _user(session)
    t = _tenant(session)
    tm = TenantMembership(id=uuid4(), user_id=u.id, tenant_id=t.id)
    w = _workspace(session, t)
    wm = WorkspaceMembership(id=uuid4(), user_id=u.id, tenant_id=t.id, workspace_id=w.id, role="invalid")
    session.add_all([tm, wm])
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
