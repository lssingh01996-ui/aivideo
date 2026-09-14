"""Phase 1A database connection. Env-based DATABASE_URL, no hardcoded creds."""
from __future__ import annotations
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL not set; see .env.example")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionFactory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
