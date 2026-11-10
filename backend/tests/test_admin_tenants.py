"""Cadastro de tenants e usuários contra um PostgreSQL + TimescaleDB real (RLS de verdade).

Pulados sem ``OPENMON_TEST_PG`` (ver tests/pgsupport.py).
"""
import pytest
from fastapi.testclient import TestClient

from openmon.api import auth, authlog, security
from openmon.db import pool

from pgsupport import app_dsn, create_database, requires_pg, reset_data, sql

pytestmark = requires_pg

ADMIN_PW = "Senha-Do-Admin-2026"
TEMP_PW = "Provisoria-Forte-81"
NEW_PW = "Nova-Senha-Do-Cliente-7"


@pytest.fixture(scope="module")
def database():
    create_database()


@pytest.fixture()
def client(database, tmp_path, monkeypatch):
    import asyncpg

    for name, sub in (("OPENMON_STATE_DIR", "state"), ("OPENMON_LOG_DIR", "log"), ("OPENMON_DB_CONFIG_DIR", "etc")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    authlog.reset()
    reset_data()
    sql("""INSERT INTO users (username, display_name, auth_source, password_hash, role_id)
           SELECT 'admin', 'Admin', 'local', %s, id FROM roles WHERE code = 'global_admin'""",
        security.hash_password(ADMIN_PW))
    monkeypatch.setattr(auth, "store", auth.PgAuthStore())
    state = {}

    async def get_pool():
        if "p" not in state:
            state["p"] = await asyncpg.create_pool(app_dsn(), min_size=0, max_size=4,
                                                   server_settings={"search_path": "openmon"})
        return state["p"]
    monkeypatch.setattr(pool, "get_pool", get_pool)
    from openmon.api.main import app
    with TestClient(app, base_url="https://testserver") as c:
        yield c
        if "p" in state:
            c.portal.call(state["p"].close)
    authlog.reset()


def login(c, username="admin", password=ADMIN_PW, status=200):
    c.cookies.clear()
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == status, r.text
    return r.json().get("csrf_token"), r.json()


def h(csrf):
    return {"X-CSRF-Token": csrf}


def new_tenant(c, csrf, slug="acme", name="ACME S.A.", **extra):
    r = c.post("/api/admin/tenants", json={"slug": slug, "name": name, **extra}, headers=h(csrf))
    assert r.status_code == 201, r.text
    return r.json()["tenant"]


def new_user(c, csrf, username="cliente1", role="client", tenant_ids=(), **extra):
    body = {"username": username, "role": role, "tenant_ids": list(tenant_ids), "password": TEMP_PW, **extra}
    r = c.post("/api/admin/users", json=body, headers=h(csrf))
    assert r.status_code == 201, r.text
    return r.json()["user"]


# -----------------------------------------------------------------------------
# Tenants
# -----------------------------------------------------------------------------
def test_tenant_crud_and_audit(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf, contact_email="noc@acme.com.br", backup_sla_hours=24)
    assert t["slug"] == "acme" and t["is_active"] and t["users"] == 0

    r = client.post("/api/admin/tenants", json={"slug": "acme", "name": "Outra"}, headers=h(csrf))
    assert r.status_code == 409
    assert client.post("/api/admin/tenants", json={"slug": "Acme Ltda", "name": "x" * 3},
                       headers=h(csrf)).status_code == 422
    assert client.post("/api/admin/tenants", json={"slug": "ok-slug", "name": "Ok", "contact_email": "sem-arroba"},
                       headers=h(csrf)).status_code == 422

    r = client.put(f"/api/admin/tenants/{t['id']}", json={"slug": "acme", "name": "ACME Brasil", "is_active": False},
                   headers=h(csrf))
    assert r.status_code == 200 and r.json()["tenant"]["name"] == "ACME Brasil"
    assert not r.json()["tenant"]["is_active"]

    tenants = client.get("/api/admin/tenants").json()["tenants"]
    assert [x["slug"] for x in tenants] == ["datacenter", "acme"]

    assert client.delete(f"/api/admin/tenants/{t['id']}", headers=h(csrf)).status_code == 200
    actions = [r[0] for r in sql("SELECT action FROM audit_log WHERE object_type = 'tenant' ORDER BY time")]
    assert actions == ["tenant.create", "tenant.deactivate", "tenant.delete"]


def test_provider_tenant_is_protected(client):
    csrf, _ = login(client)
    provider = client.get("/api/admin/tenants").json()["tenants"][0]
    assert provider["is_provider"]
    body = {"slug": provider["slug"], "name": provider["name"], "is_active": False}
    assert client.put(f"/api/admin/tenants/{provider['id']}", json=body, headers=h(csrf)).status_code == 422
    assert client.delete(f"/api/admin/tenants/{provider['id']}", headers=h(csrf)).status_code == 422


def test_tenant_with_users_is_not_deleted(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    new_user(client, csrf, tenant_ids=[t["id"]])
    r = client.delete(f"/api/admin/tenants/{t['id']}", headers=h(csrf))
    assert r.status_code == 409 and "Desative" in r.json()["detail"]


def test_mutations_require_csrf(client):
    login(client)
    assert client.post("/api/admin/tenants", json={"slug": "acme", "name": "ACME"}).status_code == 403
    assert client.post("/api/admin/users", json={"username": "x1", "role": "operator"}).status_code == 403


# -----------------------------------------------------------------------------
# Usuários
# -----------------------------------------------------------------------------
def test_user_validation(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    base = {"username": "joao", "role": "client", "password": TEMP_PW}
    cases = [
        ({**base, "tenant_ids": []}, "pelo menos um tenant"),
        ({**base, "tenant_ids": [999999]}, "inexistente"),
        ({**base, "tenant_ids": [t["id"]], "password": "curta"}, "12 caracteres"),
        ({**base, "tenant_ids": [t["id"]], "password": "joao-1234567890"}, "nome de usuário"),
        ({**base, "tenant_ids": [t["id"]], "role": "superuser"}, "Perfil inválido"),
        ({**base, "tenant_ids": [t["id"]], "username": "joão silva"}, "Usuário inválido"),
    ]
    for body, msg in cases:
        r = client.post("/api/admin/users", json=body, headers=h(csrf))
        assert r.status_code == 422 and msg in r.json()["detail"], (body, r.text)
    new_user(client, csrf, "joao", tenant_ids=[t["id"]])
    r = client.post("/api/admin/users", json={**base, "username": "JOAO", "tenant_ids": [t["id"]]}, headers=h(csrf))
    assert r.status_code == 409


def test_global_roles_have_no_tenant_links(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    u = new_user(client, csrf, "noc", role="operator", tenant_ids=[t["id"]])
    assert u["scope"] == "global" and u["tenants"] == []


def test_client_first_login_must_change_password_and_sees_only_own_tenant(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    beta = new_tenant(client, csrf, "beta", "Beta Ltda")
    new_user(client, csrf, "cliente1", tenant_ids=[acme["id"]], display_name="Cliente ACME")
    new_user(client, csrf, "cliente2", tenant_ids=[beta["id"]])
    sql("INSERT INTO assets (tenant_id, asset_type, name) VALUES (%s, 'vm', 'vm-acme'), (%s, 'vm', 'vm-beta')",
        acme["id"], beta["id"])

    csrf, body = login(client, "cliente1", TEMP_PW)
    assert body["redirect"] == "/senha.html" and body["user"]["must_change_password"]
    # Enquanto não trocar a senha, nada além de /me, /password e /logout
    assert client.get("/api/admin/tenants").json()["detail"] == auth.PASSWORD_CHANGE_FIRST

    bad = client.post("/api/auth/password", json={"current_password": "errada", "new_password": NEW_PW},
                      headers=h(csrf))
    assert bad.status_code == 422
    ok = client.post("/api/auth/password", json={"current_password": TEMP_PW, "new_password": NEW_PW},
                     headers=h(csrf))
    assert ok.status_code == 200, ok.text

    csrf, body = login(client, "cliente1", NEW_PW)
    assert body["redirect"] == "/home.html"
    me = client.get("/api/auth/me").json()["user"]
    assert me["tenants"] == ["ACME S.A."] and not me["must_change_password"]
    # Cliente não administra nada nem lista todos os tenants
    for path in ("/api/admin/tenants", "/api/admin/users", "/api/admin/roles"):
        assert client.get(path).status_code == 403, path
    assert client.post("/api/admin/tenants", json={"slug": "x-y", "name": "Xy"}, headers=h(csrf)).status_code == 403

    # Segunda barreira (RLS no banco), com o mesmo contexto que a sessão do cliente usa
    uid = sql("SELECT id FROM users WHERE username = 'cliente1'")[0][0]

    async def as_client():
        async with pool.transaction(uid, False, [acme["id"]]) as conn:
            return ([r["slug"] for r in await conn.fetch("SELECT slug FROM tenants ORDER BY id")],
                    [r["name"] for r in await conn.fetch("SELECT name FROM assets ORDER BY id")],
                    sorted(r["username"] for r in await conn.fetch("SELECT username FROM users")))
    tenants, assets, users = client.portal.call(as_client)
    assert tenants == ["acme"] and assets == ["vm-acme"] and users == ["cliente1"]


def test_deactivated_tenant_blocks_client_login(client):
    csrf, _ = login(client)
    t = new_tenant(client, csrf)
    new_user(client, csrf, "cliente1", tenant_ids=[t["id"]], must_change_password=False)
    login(client, "cliente1", TEMP_PW)
    csrf, _ = login(client)
    client.put(f"/api/admin/tenants/{t['id']}", json={"slug": "acme", "name": "ACME", "is_active": False},
               headers=h(csrf))
    login(client, "cliente1", TEMP_PW, status=401)
    assert sql("SELECT reason FROM login_attempts ORDER BY time DESC LIMIT 1")[0][0] == "no_active_tenant"


def test_deactivate_and_reset_password_end_sessions(client):
    csrf, _ = login(client)
    u = new_user(client, csrf, "noc", role="operator", must_change_password=False)
    login(client, "noc", TEMP_PW)
    noc_cookie = client.cookies.get(auth.COOKIE)
    # Operador lista tenants, mas não cria nem gerencia usuários
    r = client.get("/api/admin/tenants")
    assert r.status_code == 200 and r.json()["can_manage"] is False
    assert client.get("/api/admin/users").status_code == 403

    csrf, _ = login(client)
    r = client.post(f"/api/admin/users/{u['id']}/password", json={"password": "Outra-Senha-Forte-22"},
                    headers=h(csrf))
    assert r.status_code == 200
    admin_cookie = client.cookies.get(auth.COOKIE)
    client.cookies.set(auth.COOKIE, noc_cookie)
    assert client.get("/api/auth/me").status_code == 401  # sessão derrubada
    _, body = login(client, "noc", "Outra-Senha-Forte-22")
    assert body["user"]["must_change_password"]
    noc_cookie = client.cookies.get(auth.COOKIE)

    client.cookies.set(auth.COOKIE, admin_cookie)
    r = client.put(f"/api/admin/users/{u['id']}", json={"role": "operator", "is_active": False}, headers=h(csrf))
    assert r.status_code == 200 and not r.json()["user"]["is_active"]
    client.cookies.set(auth.COOKIE, noc_cookie)
    assert client.get("/api/auth/me").status_code == 401
    login(client, "noc", "Outra-Senha-Forte-22", status=401)


def test_last_global_admin_is_protected(client):
    csrf, _ = login(client)
    me = client.get("/api/auth/me").json()["user"]
    r = client.put(f"/api/admin/users/{me['id']}", json={"role": "operator"}, headers=h(csrf))
    assert r.status_code == 422
    assert client.delete(f"/api/admin/users/{me['id']}", headers=h(csrf)).status_code == 422

    other = new_user(client, csrf, "admin2", role="global_admin", must_change_password=False)
    # Rebaixar o outro admin é permitido enquanto este continuar ativo
    r = client.put(f"/api/admin/users/{other['id']}", json={"role": "operator"}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["user"]["role"] == "operator"
    assert client.delete(f"/api/admin/users/{other['id']}", headers=h(csrf)).status_code == 200
    assert [r["username"] for r in client.get("/api/admin/users").json()["users"]] == ["admin"]


def test_unlock_clears_lockout(client):
    csrf, _ = login(client)
    u = new_user(client, csrf, "noc", role="operator", must_change_password=False)
    for _ in range(5):
        login(client, "noc", "senha-errada-123", status=401)
    login(client, "noc", TEMP_PW, status=429)
    csrf, _ = login(client)
    listed = {x["username"]: x for x in client.get("/api/admin/users").json()["users"]}
    assert listed["noc"]["locked"]
    assert client.post(f"/api/admin/users/{u['id']}/unlock", headers=h(csrf)).status_code == 200
    login(client, "noc", TEMP_PW)


def test_users_filter_by_tenant(client):
    csrf, _ = login(client)
    a = new_tenant(client, csrf)
    b = new_tenant(client, csrf, "beta", "Beta")
    new_user(client, csrf, "c-a", tenant_ids=[a["id"]])
    new_user(client, csrf, "c-ab", tenant_ids=[a["id"], b["id"]])
    new_user(client, csrf, "c-b", tenant_ids=[b["id"]])
    names = [u["username"] for u in client.get(f"/api/admin/users?tenant_id={b['id']}").json()["users"]]
    assert names == ["c-ab", "c-b"]
    t = {x["slug"]: x for x in client.get("/api/admin/tenants").json()["tenants"]}
    assert t["acme"]["users"] == 2 and t["beta"]["users"] == 2
