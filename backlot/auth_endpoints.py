"""Authentication endpoints for Phase 1B Step 8."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from db.models import User
from lib.auth_hash import hash_password, verify_password
from lib.db import SessionFactory

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthCredentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class AuthResponse(BaseModel):
    id: str
    email: EmailStr
    is_active: bool


def _user_response(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "is_active": user.is_active,
    }


@router.post("/register", status_code=201)
async def register(credentials: AuthCredentials) -> dict:
    email = str(credentials.email).strip().lower()

    if len(credentials.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters.",
        )

    db = SessionFactory()
    try:
        user = User(
            email=email,
            password_hash=hash_password(credentials.password),
            is_active=True,
        )
        db.add(user)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="Email already registered.",
            )

        db.refresh(user)
        return _user_response(user)
    finally:
        db.close()


@router.post("/login", response_model=AuthResponse)
async def login(request: Request, credentials: AuthCredentials) -> dict:
    email = str(credentials.email).strip().lower()

    db = SessionFactory()
    try:
        user = db.scalar(select(User).where(User.email == email))

        if (
            user is None
            or not user.is_active
            or not verify_password(credentials.password, user.password_hash)
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password.",
            )

        request.session.clear()
        request.session["user_id"] = str(user.id)

        return _user_response(user)
    finally:
        db.close()


@router.post("/logout")
async def logout(request: Request) -> dict:
    request.session.clear()
    return {"ok": True}
