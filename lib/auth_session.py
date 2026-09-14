"""Phase 1B Step 7: Authenticated-user identity foundation.

Provides:
- SessionMiddleware configuration wired into backlot/server.py.
- get_current_user(request) dependency using the established
  lib.db.SessionFactory pattern (sessions properly closed).

Security:
- Starlette SessionMiddleware is a SIGNED CLIENT-SIDE cookie, not
  server-side storage. Only user_id is stored.
- SESSION_SECRET must be set; fail clearly otherwise.
- No plaintext passwords, no password_hash exposure, no credential logging.
- HttpOnly, SameSite, Secure, max_age configurable.
"""
from __future__ import annotations

import os
import uuid

from starlette.requests import Request
from sqlalchemy.orm import Session


def get_session_settings() -> dict:
    session_secret = os.environ.get("SESSION_SECRET")
    if not session_secret:
        raise ValueError(
            "SESSION_SECRET not set — set it in .env (e.g. a 32+ hex string). "
            "Production must use a distinct secret and SESSION_COOKIE_SECURE=true."
        )

    max_age_raw = os.environ.get("SESSION_MAX_AGE", "604800")
    try:
        max_age = int(max_age_raw)
    except ValueError as exc:
        raise ValueError(f"SESSION_MAX_AGE must be an integer (seconds), got {max_age_raw!r}") from exc

    secure = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    httponly = os.environ.get("SESSION_COOKIE_HTTPONLY", "true").lower() in ("1", "true", "yes")
    same_site = os.environ.get("SESSION_COOKIE_SAME_SITE", "lax")

    return {
        "secret_key": session_secret,
        "same_site": same_site,
        "https_only": secure,
        "max_age": max_age,
        "httponly": httponly,
    }


def get_current_user(request: Request):
    """Return the authenticated User for the current session, or None.

    Reads request.session["user_id"], validates UUID, loads User via
    lib.db.SessionFactory (properly closed), requires is_active=True.
    """
    from lib.db import SessionFactory
    from db.models import User

    token = request.session.get("user_id")
    if not token:
        return None

    try:
        uid = uuid.UUID(str(token))
    except Exception:
        return None

    db: Session = SessionFactory()
    try:
        u = db.get(User, uid)
        if u is None or not getattr(u, "is_active", False):
            return None
        return u
    finally:
        db.close()
