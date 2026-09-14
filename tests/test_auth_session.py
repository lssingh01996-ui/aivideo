"""Phase 1B Step 7: authentication/session identity — get_current_user() unit tests.

Run in vid01_test isolation (reuse existing DATABASE_URL gate from
test_saas_identity where possible; otherwise load .env directly).
"""

import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

# Isolate to vid01_test before importing lib.db/models
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")
_RAW = os.environ.get("DATABASE_URL", "")
if _RAW:
    _p = urlsplit(_RAW)
    os.environ["DATABASE_URL"] = urlunsplit((_p.scheme, _p.netloc, "/vid01_test", _p.query, _p.fragment))

import pytest
from sqlalchemy.orm import sessionmaker

from db.models import User, Tenant  # noqa: E402
from lib.db import Base, engine  # noqa: E402


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="module", autouse=True)
def _auth_tables():
    Base.metadata.create_all(bind=engine)
    yield
    # do not drop — module-scoped tables shared with other tests; dropping causes flakiness


@pytest.fixture
def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _active_user(db, *, is_active=True):
    u = User(
        id=uuid.uuid4(),
        email=f"t{uuid.uuid4().hex[:6]}@ex.com",
        password_hash="fake-hash-for-session-test",
        is_active=is_active,
    )
    db.add(u)
    db.commit()
    return u


class DummyRequest:
    session: dict

    def __init__(self, session):
        self.session = session


def test_get_current_user_missing_session_returns_none(db):
    from lib.auth_session import get_current_user
    req = DummyRequest({})
    assert get_current_user(req) is None


def test_get_current_user_malformed_uuid_returns_none(db):
    from lib.auth_session import get_current_user
    req = DummyRequest({"user_id": "not-a-uuid"})
    assert get_current_user(req) is None


def test_get_current_user_nonexistent_returns_none(db):
    from lib.auth_session import get_current_user
    req = DummyRequest({"user_id": str(uuid.uuid4())})
    assert get_current_user(req) is None


def test_get_current_user_inactive_returns_none(db):
    from lib.auth_session import get_current_user
    u = _active_user(db, is_active=False)
    req = DummyRequest({"user_id": str(u.id)})
    assert get_current_user(req) is None


def test_get_current_user_valid_active_returns_user(db):
    from lib.auth_session import get_current_user
    u = _active_user(db, is_active=True)
    req = DummyRequest({"user_id": str(u.id)})
    got = get_current_user(req)
    assert got is not None
    assert got.id == u.id
    assert not hasattr(got, "password_hash") or got.password_hash is not None  # loaded, but never serialized


def test_session_settings_missing_secret_raises(db, monkeypatch):
    from lib.auth_session import get_session_settings
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    with pytest.raises(ValueError, match="SESSION_SECRET not set"):
        get_session_settings()


def test_session_cookie_security_defaults(db, monkeypatch):
    from lib.auth_session import get_session_settings
    monkeypatch.setenv("SESSION_SECRET", "a" * 32)
    monkeypatch.setenv("SESSION_MAX_AGE", "3600")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    s = get_session_settings()
    assert s["httponly"] is True  # must be true
    assert s["max_age"] == 3600
    assert s["https_only"] is False  # explicit false for dev
