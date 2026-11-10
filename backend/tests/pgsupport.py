"""Banco real (PostgreSQL + TimescaleDB) para os testes de RLS e do cadastro.

Defina ``OPENMON_TEST_PG`` com o DSN de um superusuário, por exemplo:

    docker run -d --name omdb -e POSTGRES_PASSWORD=pgtest -p 55432:5432 timescale/timescaledb-ha:pg17
    OPENMON_TEST_PG=postgresql://postgres:pgtest@127.0.0.1:55432/postgres pytest

Sem a variável, esses testes são pulados. O banco ``openmon`` do servidor
indicado é recriado do zero, com os mesmos papéis e migrations do deploy, e a
API conecta como ``openmon_app`` (sem BYPASSRLS), como em produção.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlsplit, urlunsplit

import pytest

from openmon.db import migrations

ADMIN_DSN = os.environ.get("OPENMON_TEST_PG", "")
APP_PASSWORD = "app-test-password"
requires_pg = pytest.mark.skipif(not ADMIN_DSN, reason="OPENMON_TEST_PG não definido (banco de teste)")


def _dsn(db: str, user: str | None = None, password: str | None = None) -> str:
    u = urlsplit(ADMIN_DSN)
    netloc = u.netloc
    if user:
        netloc = f"{user}:{password}@{u.hostname}:{u.port or 5432}"
    return urlunsplit((u.scheme, netloc, "/" + db, u.query, ""))


def admin_dsn() -> str:
    return _dsn("openmon")


def app_dsn() -> str:
    return _dsn("openmon", "openmon_app", APP_PASSWORD)


def create_database() -> None:
    import psycopg

    with psycopg.connect(_dsn("postgres"), autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS openmon WITH (FORCE)")
        for role in ("openmon_owner", "openmon_app"):
            if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
                c.execute(f"CREATE ROLE {role}")
        c.execute("ALTER ROLE openmon_owner LOGIN")  # como no deploy: jobs do TimescaleDB rodam como o dono
        c.execute(f"ALTER ROLE openmon_app LOGIN PASSWORD '{APP_PASSWORD}' NOBYPASSRLS")
        c.execute("CREATE DATABASE openmon OWNER openmon_owner")
    with psycopg.connect(admin_dsn(), autocommit=True) as c:
        boot = "\n".join(line for line in migrations.bootstrap_sql().splitlines() if not line.startswith("\\"))
        c.execute(boot)
        for mig in migrations.discover():
            sql = re.sub(r"^\\.*$", "", mig.wrapped(), flags=re.M)
            c.execute(sql)


def reset_data() -> None:
    """Volta ao estado logo após o deploy (só o tenant provedor, nenhum usuário)."""
    import psycopg

    with psycopg.connect(admin_dsn(), autocommit=True) as c:
        c.execute("SET search_path = openmon, public")
        c.execute("TRUNCATE user_sessions, user_tenants, login_attempts, assets, integrations CASCADE")
        c.execute("DELETE FROM audit_log")
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM tenants WHERE NOT is_provider")


def sql(query: str, *params):
    import psycopg

    with psycopg.connect(admin_dsn(), autocommit=True) as c:
        c.execute("SET search_path = openmon, public")
        cur = c.execute(query, params or None)
        return cur.fetchall() if cur.description else None
