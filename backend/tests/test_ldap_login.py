"""Login pelo AD/LDAP de ponta a ponta: OpenLDAP com TLS + PostgreSQL/TimescaleDB reais.

Precisa de ``OPENMON_TEST_PG`` e de um OpenLDAP preparado como em
docs/06-active-directory.md (``OPENMON_TEST_LDAP_URL``, ``OPENMON_TEST_LDAP_CA``).
"""
import os

import pytest

from openmon import vault
from openmon.api import auth

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant  # noqa: F401 (fixtures)

LDAP_URL = os.environ.get("OPENMON_TEST_LDAP_URL", "")
LDAP_CA = os.environ.get("OPENMON_TEST_LDAP_CA", "")
pytestmark = [requires_pg, pytest.mark.skipif(not (LDAP_URL and LDAP_CA), reason="OPENMON_TEST_LDAP_* não definido")]

BASE = "dc=openmon,dc=test"
SVC = f"uid=svc-openmon,ou=People,{BASE}"


@pytest.fixture(autouse=True)
def master_key(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    sql("DELETE FROM ldap_directories")
    sql("DELETE FROM credentials")
    sql("DELETE FROM vault_keys")
    yield
    vault.reset()


def directory(tenant_id, **over):
    body = {"name": "OpenLDAP de teste", "urls": [LDAP_URL], "security": "ldaps", "base_dn": BASE,
            "bind_dn": SVC, "bind_password": "Svc-Bind-Pass-1",
            "user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))", "group_attribute": "memberOf",
            "ca_cert_pem": open(LDAP_CA).read(),
            "mappings": [{"group_dn": f"cn=openmon-noc,ou=Groups,{BASE}", "role": "operator"},
                         {"group_dn": f"cn=cliente-acme,ou=Groups,{BASE}", "role": "client", "tenant_id": tenant_id}]}
    body.update(over)
    return body


def test_configure_test_and_login_with_groups(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    body = directory(acme["id"])

    r = client.post("/api/admin/ldap/test", json={**body, "test_username": "carlos",
                                                 "test_password": "Carlos-Ldap-Pass-1"}, headers=h(csrf))
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert r.json()["access"] == {"role": "client", "tenants": ["ACME S.A."]}

    r = client.post("/api/admin/ldap", json=body, headers=h(csrf))
    assert r.status_code == 201, r.text
    d = r.json()["directory"]
    assert d["has_password"] and "bind_password" not in d and len(d["mappings"]) == 2
    # No banco a senha só existe cifrada
    row = sql("SELECT username, ciphertext FROM credentials")[0]
    assert row[0] == SVC and b"Svc-Bind-Pass-1" not in bytes(row[1])

    # Editar sem senha mantém a guardada; o teste usa a do cofre
    r = client.put(f"/api/admin/ldap/{d['id']}", json={**body, "bind_password": None, "timeout_seconds": 7},
                   headers=h(csrf))
    assert r.status_code == 200, r.text
    r = client.post("/api/admin/ldap/test", json={**body, "bind_password": None, "directory_id": d["id"]},
                    headers=h(csrf))
    assert r.json()["ok"], r.text

    # Cliente do AD: provisionado no primeiro login, só com o tenant do grupo
    _, out = login(client, "carlos", "Carlos-Ldap-Pass-1")
    me = client.get("/api/auth/me").json()["user"]
    assert me["auth_source"] == "ldap" and me["role"] == "client" and me["tenants"] == ["ACME S.A."]
    assert out["redirect"] == "/painel.html" and not me["must_change_password"]
    assert client.get("/api/admin/tenants").status_code == 403

    # Operador pelo grupo NOC
    login(client, "maria", "Maria-Ldap-Pass-1")
    assert client.get("/api/auth/me").json()["user"]["role"] == "operator"

    # Senha errada, usuário sem grupo e inexistente
    login(client, "carlos", "errada-errada", status=401)
    r = client.post("/api/auth/login", json={"username": "semgrupo", "password": "SemGrupo-Pass-1"})
    assert r.status_code == 403 and "grupo" in r.json()["detail"]
    login(client, "ninguem", "x" * 12, status=401)
    reasons = [r[0] for r in sql("SELECT reason FROM login_attempts WHERE NOT success ORDER BY time")]
    assert reasons == ["bad_password", "no_group", "unknown_user"]
    assert {r[0] for r in sql("SELECT auth_source FROM user_sessions")} == {"local", "ldap"}


def test_admin_disables_ldap_user_and_local_wins(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    client.post("/api/admin/ldap", json=directory(acme["id"]), headers=h(csrf))
    login(client, "carlos", "Carlos-Ldap-Pass-1")
    csrf, _ = login(client)
    carlos = next(u for u in client.get("/api/admin/users").json()["users"] if u["username"] == "carlos")
    r = client.put(f"/api/admin/users/{carlos['id']}",
                   json={"role": "client", "tenant_ids": [acme["id"]], "is_active": False}, headers=h(csrf))
    assert r.status_code == 200
    login(client, "carlos", "Carlos-Ldap-Pass-1", status=401)

    csrf, _ = login(client)
    # Conta local com o mesmo nome do AD: a local tem precedência (o AD nem é consultado)
    r = client.post("/api/admin/users", json={"username": "maria", "role": "operator",
                                              "password": "Senha-Local-NOC-1", "must_change_password": False},
                    headers=h(csrf))
    assert r.status_code == 201
    login(client, "maria", "Maria-Ldap-Pass-1", status=401)
    login(client, "maria", "Senha-Local-NOC-1")


def test_ldap_down_does_not_count_as_failure(client):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    body = directory(acme["id"], urls=["ldaps://ldap.openmon.test:1"], timeout_seconds=2)
    assert client.post("/api/admin/ldap", json=body, headers=h(csrf)).status_code == 201
    r = client.post("/api/auth/login", json={"username": "carlos", "password": "Carlos-Ldap-Pass-1"})
    assert r.status_code == 503 and "Active Directory" in r.json()["detail"]
    assert sql("SELECT count(*) FROM login_attempts WHERE username = 'carlos'")[0][0] == 0


def test_rejects_plain_ldap_and_requires_admin(client):
    csrf, _ = login(client)
    # Não existe opção sem TLS: o esquema sai da "Segurança" (ldap:// colado vira ldaps:// com LDAPS)
    r = client.post("/api/admin/ldap", json=directory(None, security="none", mappings=[]), headers=h(csrf))
    assert r.status_code == 422
    r = client.post("/api/admin/ldap", json=directory(None, urls=["ldap://dc1.empresa.local"], mappings=[]),
                    headers=h(csrf))
    assert r.status_code == 201 and r.json()["directory"]["urls"] == ["ldaps://dc1.empresa.local:636"]
    sql("DELETE FROM ldap_directories")
    r = client.post("/api/admin/ldap", json=directory(None, urls=["ldap://dc 1"], mappings=[]), headers=h(csrf))
    assert r.status_code == 422 and "inválido" in r.json()["detail"]
    r = client.post("/api/admin/ldap", json=directory(None), headers=h(csrf))
    assert r.status_code == 422 and "tenant" in r.json()["detail"]
    client.post("/api/admin/users", json={"username": "noc", "role": "operator", "password": "Senha-Operador-123",
                                          "must_change_password": False}, headers=h(csrf))
    login(client, "noc", "Senha-Operador-123")
    assert client.get("/api/admin/ldap").status_code == 403
    assert auth.COOKIE in client.cookies


def test_dc_name_port_and_ignore_certificate(client):
    """Como no OpenFlow: nome do DC sem prefixo, porta separada e a opção de não verificar o certificado."""
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    host, port = LDAP_URL.split("://", 1)[1].rstrip("/").split(":")
    body = directory(acme["id"], urls=[f"{host}, {host}"], port=int(port), ca_cert_pem=None)
    # Sem a CA interna e verificando: erro de certificado, com a dica da caixa
    r = client.post("/api/admin/ldap/test", json=body, headers=h(csrf)).json()
    assert not r["ok"] and "Verificar o certificado" in r["steps"][0]["detail"], r
    # Sem verificar: conecta (continua LDAPS) e o login funciona
    body["verify_tls"] = False
    r = client.post("/api/admin/ldap/test", json=body, headers=h(csrf)).json()
    assert r["ok"] and "NÃO verificado" in r["steps"][0]["detail"], r
    d = client.post("/api/admin/ldap", json=body, headers=h(csrf)).json()["directory"]
    assert d["urls"] == [f"ldaps://{host}:{port}"] and d["hosts"] == [host] and d["port"] == int(port)
    assert d["verify_tls"] is False
    r = client.post("/api/auth/login", json={"username": "carlos", "password": "Carlos-Ldap-Pass-1"})
    assert r.status_code == 200, r.text
    # Editar e voltar a verificar (sem trocar a senha da conta de serviço)
    csrf, _ = login(client)
    d = client.put(f"/api/admin/ldap/{d['id']}", json={**body, "verify_tls": True, "bind_password": None},
                   headers=h(csrf)).json()["directory"]
    assert d["verify_tls"] is True


def test_ad_user_created_by_admin_has_fixed_profile(client):
    """Como no OpenFlow: Novo usuário com origem Active Directory, sem senha, perfil e tenant fixos."""
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    beta = new_tenant(client, csrf, "beta", "Beta")
    # Sem AD configurado, a origem AD é recusada
    r = client.post("/api/admin/users", json={"username": "semgrupo", "role": "operator", "auth_source": "ldap"},
                    headers=h(csrf))
    assert r.status_code == 422 and "AD/LDAP" in r.json()["detail"]
    assert client.post("/api/admin/ldap", json=directory(acme["id"]), headers=h(csrf)).status_code == 201
    assert client.get("/api/admin/users").json()["ldap_directories"][0]["name"] == "OpenLDAP de teste"

    # "semgrupo" não está em nenhum grupo mapeado: só entra porque foi cadastrado aqui, como Operador
    r = client.post("/api/admin/users", json={"username": "semgrupo", "role": "operator", "auth_source": "ldap"},
                    headers=h(csrf))
    assert r.status_code == 201, r.text
    u = r.json()["user"]
    assert u["auth_source"] == "ldap" and u["profile_from_groups"] is False and not u["must_change_password"]
    assert sql("SELECT password_hash FROM users WHERE username = 'semgrupo'")[0][0] is None
    login(client, "semgrupo", "SemGrupo-Pass-1")
    assert client.get("/api/auth/me").json()["user"]["role"] == "operator"
    login(client, "semgrupo", "errada-errada", status=401)

    # carlos (grupo cliente-acme) cadastrado fixo no tenant Beta: os grupos não mudam o que foi definido aqui
    csrf, _ = login(client)
    r = client.post("/api/admin/users", json={"username": "carlos", "role": "client", "tenant_ids": [beta["id"]],
                                              "auth_source": "ldap"}, headers=h(csrf))
    cid = r.json()["user"]["id"]
    login(client, "carlos", "Carlos-Ldap-Pass-1")
    assert client.get("/api/auth/me").json()["user"]["tenants"] == ["Beta"]
    # Voltar a seguir os grupos: no próximo login vira cliente da ACME
    csrf, _ = login(client)
    r = client.put(f"/api/admin/users/{cid}", json={"role": "client", "tenant_ids": [beta["id"]],
                                                     "profile_from_groups": True}, headers=h(csrf))
    assert r.json()["user"]["profile_from_groups"] is True
    login(client, "carlos", "Carlos-Ldap-Pass-1")
    assert client.get("/api/auth/me").json()["user"]["tenants"] == ["ACME S.A."]
    assert sql("SELECT external_dn FROM users WHERE username = 'carlos'")[0][0].startswith("uid=carlos")
