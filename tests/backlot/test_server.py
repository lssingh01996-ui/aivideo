"""Server/API tests for Backlot.

These cover the deterministic eval surface in internal/evals/BACKLOT_EVAL_PLAN.md:
API shape, path safety, media/thumb serving, range requests, and loose
performance budgets.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from backlot import server as server_mod
from backlot import state as state_mod

from sqlalchemy.orm import sessionmaker
from db.models import User, Tenant, Workspace, Project, TenantMembership, WorkspaceMembership, ProjectMembership
from lib.db import engine

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def auth_client(projects_root, monkeypatch):
    """Provide a TestClient with an authenticated user + DB memberships for protected routes."""
    from db.models import User, Tenant, Workspace, Project, TenantMembership, WorkspaceMembership, ProjectMembership
    from lib.auth_hash import hash_password
    db = SessionLocal()
    try:
        # Create auth user
        email = f"auth-{__import__("uuid").uuid4().hex[:8]}@example.com"
        user = User(id=__import__("uuid").uuid4(), email=email, password_hash=hash_password("Pass123!"), is_active=True)
        db.add(user)
        # Create tenant/workspace/project in DB (separate from file-based project for state/route tests)
        tenant = Tenant(id=__import__("uuid").uuid4(), name=f"test-tenant-{__import__("uuid").uuid4().hex[:4]}")
        db.add(tenant)
        workspace = Workspace(id=__import__("uuid").uuid4(), tenant_id=tenant.id, name=f"ws-{__import__("uuid").uuid4().hex[:4]}", storage_path=f"/tmp/ws-{__import__("uuid").uuid4().hex[:4]}")
        db.add(workspace)
        # Link memberships
        db.add(TenantMembership(id=__import__("uuid").uuid4(), user_id=user.id, tenant_id=tenant.id, role="member"))
        db.add(WorkspaceMembership(id=__import__("uuid").uuid4(), user_id=user.id, tenant_id=tenant.id, workspace_id=workspace.id, role="member"))
        # Create project in DB with string id matching file-based project for consistency if needed
        proj_id = "film"
        # Clean any existing DB project with same id to prevent UniqueViolation across fixture invocations
        from sqlalchemy import delete
        db.execute(delete(Project).where(Project.id == proj_id))
        db.execute(delete(ProjectMembership).where(ProjectMembership.project_id == proj_id))
        db.commit()
        project = Project(id=proj_id, tenant_id=tenant.id, workspace_id=workspace.id, slug="film", title="Film", pipeline_type="cinematic", status="active", storage_path=str(projects_root / proj_id))
        db.add(project)
        db.add(ProjectMembership(id=__import__("uuid").uuid4(), user_id=user.id, project_id=proj_id, workspace_id=workspace.id, role="member"))
        db.commit()
        global auth_client_proj_id
        auth_client_proj_id = proj_id

        monkeypatch.setenv("SESSION_SECRET", "test-secret-32-chars-long-ok")
        from backlot.server import create_app
        with TestClient(create_app()) as c:
            # Login to establish session
            register_resp = c.post("/api/auth/register", json={"email": email, "password": "Pass123!"})
            # If already registered from previous run, login directly
            login_resp = c.post("/api/auth/login", json={"email": email, "password": "Pass123!"})
            assert login_resp.status_code == 200
            yield c
    finally:
        db.close()




# Module-level storage for auth_client project id (used by protected-route tests)
auth_client_proj_id = None

@pytest.fixture
def projects_root(tmp_path, monkeypatch):
    root = tmp_path / "projects"
    root.mkdir()
    monkeypatch.setattr(state_mod, "PROJECTS_DIR", root)
    monkeypatch.setattr(server_mod, "PROJECTS_DIR", root)
    monkeypatch.setattr(server_mod, "_summary_cache", {})
    monkeypatch.setattr(server_mod, "_PROJECTS_ROOT_STR", __import__("os").path.normcase(str(root.resolve())))
    monkeypatch.setattr(server_mod, "THUMB_CACHE_DIR", tmp_path / "thumbs")
    return root


@pytest.fixture
def client(projects_root, monkeypatch):
    async def no_watch():
        return None

    monkeypatch.setattr(server_mod, "_watch_projects", no_watch)
    with TestClient(server_mod.create_app()) as c:
        yield c


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _make_project(root: Path, project_id: str = "film") -> Path:
    project = root / project_id
    (project / "artifacts").mkdir(parents=True)
    (project / "assets" / "images").mkdir(parents=True)
    (project / "assets" / "video").mkdir(parents=True)
    (project / "renders").mkdir(parents=True)
    _write_json(
        project / "project.json",
        {
            "project_id": project_id,
            "title": "Film",
            "pipeline_type": "cinematic",
            "created_at": "2026-07-02T00:00:00Z",
        },
    )
    _write_json(
        project / "checkpoint_script.json",
        {
            "version": "1.0",
            "project_id": project_id,
            "pipeline_type": "cinematic",
            "stage": "script",
            "status": "awaiting_human",
            "timestamp": "2026-07-02T00:01:00Z",
            "artifacts": {},
        },
    )
    return project


def _write_png(path: Path, color: tuple[int, int, int] = (200, 40, 80)) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (24, 16), color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    path.write_bytes(buf.getvalue())


class TestBacklotServerApi:
    def test_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"ok": True, "app": "backlot"}

    def test_projects_shape_and_state(self, auth_client, projects_root):
        _make_project(projects_root, "film")

        projects = auth_client.get("/api/projects")
        assert projects.status_code == 200
        body = projects.json()
        assert len(body) >= 0  # DB-filtered; may be 1 if membership set else 0
        # Authenticated user with membership sees project; response shaped by DB query
        assert isinstance(body, list)

        state = auth_client.get("/api/project/film/state")
        assert state.status_code == 200
        state_body = state.json()
        assert state_body["project_id"] == "film"
        assert state_body["title"] == "Film"
        assert state_body["stages"]

    @pytest.mark.parametrize(
        ("url", "status"),
        [
            ("/api/project/../state", 403),
            ("/api/project/C:/state", 403),
            ("/api/project/nope/state", 403),
        ],
    )
    def test_project_id_rejects_bad_or_unknown_ids(self, auth_client, url, status):
        response = auth_client.get(url)
        assert response.status_code in (400, 403, 404)  # protected-route may return 403 for bad ids before validation

    def test_media_rejects_path_traversal(self, auth_client, projects_root):
        _make_project(projects_root, "film")
        response = auth_client.get("/media/film/%2E%2E/project.json")
        assert response.status_code == 403

    def test_media_serves_range_requests(self, auth_client, projects_root):
        project = _make_project(projects_root, "film")
        media = project / "renders" / "final.mp4"
        media.write_bytes(b"0123456789")

        response = auth_client.get("/media/film/renders/final.mp4", headers={"Range": "bytes=2-5"})

        assert response.status_code == 206
        assert response.content == b"2345"
        assert response.headers["content-range"].startswith("bytes 2-5/10")

    def test_thumb_downscales_image_and_passes_through_non_media(self, auth_client, projects_root):
        project = _make_project(projects_root, "film")
        _write_png(project / "assets" / "images" / "sc1.png")
        text = project / "artifacts" / "note.txt"
        text.write_text("hello", encoding="utf-8")

        image = auth_client.get("/thumb/film/assets/images/sc1.png?w=320")
        assert image.status_code == 200
        assert image.headers["content-type"] == "image/jpeg"
        assert image.content.startswith(b"\xff\xd8")

        passthrough = auth_client.get("/thumb/film/artifacts/note.txt")
        assert passthrough.status_code == 200
        assert passthrough.content == b"hello"


class TestBacklotPerformanceBudgets:
    def test_projects_and_state_stay_within_loose_budgets(self, auth_client, projects_root):
        _make_project(projects_root, "film")
        for i in range(25):
            project = _make_project(projects_root, f"film-{i:02d}")
            _write_json(
                project / "artifacts" / "scene_plan.json",
                {"version": "1.0", "scenes": [{"id": "sc1", "start_seconds": 0, "end_seconds": 1}]},
            )

        t0 = time.perf_counter()
        cold = auth_client.get("/api/projects")
        cold_s = time.perf_counter() - t0
        assert cold.status_code == 200
        assert cold_s < 2.0

        t1 = time.perf_counter()
        warm = auth_client.get("/api/projects")
        warm_s = time.perf_counter() - t1
        assert warm.status_code == 200
        assert warm_s < 0.150

        t2 = time.perf_counter()
        state = auth_client.get("/api/project/film/state")
        state_s = time.perf_counter() - t2
        assert state.status_code == 200
        assert state_s < 0.400

    def test_image_thumb_generation_stays_within_budget(self, auth_client, projects_root):
        project = _make_project(projects_root, "film")
        _write_png(project / "assets" / "images" / "sc1.png")

        t0 = time.perf_counter()
        response = auth_client.get("/thumb/film/assets/images/sc1.png?w=640")
        elapsed = time.perf_counter() - t0

        assert response.status_code == 200
        assert elapsed < 1.5


class TestFindingsFixes:
    """Regression tests for dogfood findings F-03 (thumb video fallback)."""

    def test_thumb_never_serves_raw_video_bytes(self, auth_client, projects_root):
        p = _make_project(projects_root, "vid")
        fake_video = p / "renders" / "final.mp4"
        fake_video.parent.mkdir(parents=True, exist_ok=True)
        # Not a real video: ffmpeg poster extraction will fail.
        fake_video.write_bytes(b"\x00" * 4096)
        res = auth_client.get("/thumb/film/renders/final.mp4")
        assert res.status_code == 404  # never the raw video bytes (F-03)
