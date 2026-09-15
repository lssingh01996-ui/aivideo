"""Phase 1B Step 8: authentication endpoint tests."""

import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

# Isolate endpoint tests to vid01_test before importing lib.db/models/server.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")
_RAW = os.environ.get("DATABASE_URL", "")
if _RAW:
    _p = urlsplit(_RAW)
    os.environ["DATABASE_URL"] = urlunsplit(
        (_p.scheme, _p.netloc, "/vid01_test", _p.query, _p.fragment)
    )

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from db.models import User  # noqa: E402
from lib.db import Base, engine  # noqa: E402
from backlot.server import create_app  # noqa: E402


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _unique_email() -> str:
    return f"step8-{uuid.uuid4().hex}@example.com"


def _create_user(db, *, email=None, password_hash="unused", is_active=True):
    user = User(
        id=uuid.uuid4(),
        email=email or _unique_email(),
        password_hash=password_hash,
        is_active=is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _client():
    Base.metadata.create_all(bind=engine)
    return TestClient(create_app())


def test_register_valid():
    client = _client()
    email = _unique_email()

    response = client.post(
        "/api/auth/register",
        json={"email": f"  {email.upper()}  ", "password": "StrongPass123!"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email
    assert data["is_active"] is True
    assert "password_hash" not in data
    assert "password" not in data


def test_register_duplicate_email():
    client = _client()
    email = _unique_email()

    first = client.post(
        "/api/auth/register",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert first.status_code == 201

    second = client.post(
        "/api/auth/register",
        json={"email": email.upper(), "password": "AnotherPass123!"},
    )

    assert second.status_code == 400
    assert second.json()["detail"] == "Email already registered."


def test_register_weak_password():
    client = _client()

    response = client.post(
        "/api/auth/register",
        json={"email": _unique_email(), "password": "short"},
    )

    assert response.status_code == 400


def test_login_valid():
    client = _client()
    email = _unique_email()

    register = client.post(
        "/api/auth/register",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert register.status_code == 201

    response = client.post(
        "/api/auth/login",
        json={"email": email.upper(), "password": "StrongPass123!"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert data["is_active"] is True
    assert "password_hash" not in data
    assert "password" not in data

    with client:
        response = client.post(
            "/api/auth/login",
            json={"email": email, "password": "StrongPass123!"},
        )
        assert response.status_code == 200

        session_check = client.get("/api/health")
        assert session_check.status_code == 200


def test_login_wrong_password():
    client = _client()
    email = _unique_email()

    register = client.post(
        "/api/auth/register",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert register.status_code == 201

    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_inactive():
    client = _client()
    db = SessionLocal()

    try:
        from lib.auth_hash import hash_password

        email = _unique_email()
        _create_user(
            db,
            email=email,
            password_hash=hash_password("StrongPass123!"),
            is_active=False,
        )
    finally:
        db.close()

    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongPass123!"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_logout_clears():
    client = _client()
    email = _unique_email()

    register = client.post(
        "/api/auth/register",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert register.status_code == 201

    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert login.status_code == 200

    logout = client.post("/api/auth/logout")

    assert logout.status_code == 200
    assert logout.json() == {"ok": True}

    # Login again must establish a fresh session; logout itself must not fail.
    login_again = client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongPass123!"},
    )
    assert login_again.status_code == 200
