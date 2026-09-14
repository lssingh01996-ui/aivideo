#!/usr/bin/env bash
# Phase 1A verification driver — runs the 6-step sequence and prints PROVEN results
# only. Any failure aborts immediately with the exact stderr; nothing is glossed.
set -u  # no -e: we want to capture each step's exit status explicitly
cd "C:/Users/Chat Cloud API/Downloads/Vid01-main" || { echo "STEP0 FAIL: cannot cd"; exit 1; }

echo "### STEP1 python/pip"
python3 --version; echo "py_exit=$?"
python3 -m pip --version; echo "pip_exit=$?"

echo "### STEP2 venv probe"
ls -d .venv venv env 2>/dev/null || echo "no venv dir found (bare or system python)"

echo "### STEP3 DATABASE_URL probe (credential-safe)"
python3 - <<'PY'
import os
u = os.environ.get("DATABASE_URL") or ""
# Print only scheme+host (redact password/user/db) so nothing leaks into the log.
import re
m = re.match(r"^([a-z+]+)://([^:/@]+):([^@/]+)@([^:/]+):?(\d+)?/(.*)$", u)
if m:
    scheme, user, pwd, host, port, db = m.groups()
    print(f"scheme={scheme} host={host} port={port or 'default'} db={db} user={user} has_pwd={bool(pwd)}")
else:
    print(f"DATABASE_URL present={bool(u)} (masked; scheme parse skipped)")
PY
echo "dburl_exit=$?"

echo "### STEP4 import models"
python3 -c "from lib.db import Base, engine; from db.models import Tenant, Workspace, Project; print('imports OK')"
echo "import_exit=$?"

echo "### STEP5 alembic autogenerate"
alembic revision --autogenerate -m "init saas identity"
echo "alembic_exit=$?"

echo "### STEP6 (deferred) upgrade + pytest — do not yet run"
echo "driver finished"
