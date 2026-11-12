from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from openmon.api import auth, authlog, security

from tests_support import NOW, PASSWORD, FakeStore  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    for name, sub in (("OPENMON_STATE_DIR", "state"), ("OPENMON_LOG_DIR", "log"), ("OPENMON_DB_CONFIG_DIR", "etc")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    authlog.reset()
    store = FakeStore()
    monkeypatch.setattr(auth, "store", store)
    from openmon.api.main import app
    # https: o cookie é Secure e só volta por HTTPS
    with TestClient(app, base_url="https://testserver") as c:
        c.store, c.tmp = store, tmp_path
        yield c
    authlog.reset()


def login(c, password=PASSWORD, username="admin"):
    return c.post("/api/auth/login", json={"username": username, "password": password})


def test_login_sets_hardened_cookie_and_csrf(client):
    r = login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "global_admin" and body["redirect"] == "/painel.html"
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(auth.COOKIE + "=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower()
    token = client.cookies.get(auth.COOKIE)
    assert body["csrf_token"] == security.csrf_for(token) != token
    # o banco guarda só hashes
    assert list(client.store.sessions) == [security.sha256(token)]
    assert client.store.attempts[-1][2] is True


def test_me_requires_session(client):
    assert client.get("/api/auth/me").status_code == 401
    login(client)
    r = client.get("/api/auth/me")
    assert r.status_code == 200 and r.json()["user"]["username"] == "admin"
    assert r.headers["cache-control"] == "no-store"


def test_logout_requires_csrf(client):
    csrf = login(client).json()["csrf_token"]
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": "x" * 64}).status_code == 403
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_bad_password_is_generic_and_logged(client):
    a = login(client, "errada-errada-errada")
    b = login(client, PASSWORD, username="nao-existe")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    log = (client.tmp / "log" / "auth.log").read_text()
    assert log.count('"event":"auth.failure"') == 2 and "errada" not in log
    assert [x[3] for x in client.store.attempts] == ["bad_password", "unknown_user"]


def test_lockout_after_five_failures(client):
    for _ in range(5):
        assert login(client, "errada-errada-errada").status_code == 401
    r = login(client)  # senha certa, mas a conta está bloqueada
    assert r.status_code == 429
    assert '"event":"auth.locked"' in (client.tmp / "log" / "auth.log").read_text()
    assert auth.COOKIE not in client.cookies


def test_success_resets_the_user_window(client):
    for _ in range(4):
        login(client, "errada-errada-errada")
    assert login(client).status_code == 200
    assert login(client, "errada-errada-errada").status_code == 401
    assert login(client).status_code == 200


def test_unknown_users_lock_the_same_way(client):
    for _ in range(5):
        login(client, "x" * 12, username="fantasma")
    assert login(client, "x" * 12, username="fantasma").status_code == 429


def test_idle_session_expires(client):
    login(client)
    for s in client.store.sessions.values():
        s["seen"] = NOW() - timedelta(minutes=31)
    assert client.get("/api/auth/me").status_code == 401


def test_csrf_derivation_is_per_session():
    a, b = security.new_session_token(), security.new_session_token()
    assert security.csrf_for(a) != security.csrf_for(b) and len(security.csrf_for(a)) == 64


def test_password_hash_and_rehash():
    h = security.hash_password(PASSWORD)
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert security.verify_password(h, PASSWORD) == (True, None)
    assert security.verify_password(h, "outra")[0] is False
    assert security.verify_password("$2b$12$abc", PASSWORD)[0] is False


def test_argon2_cffi_21_1_without_invalidhasherror(monkeypatch):
    """Debian 13 traz argon2-cffi 21.1, que só tem InvalidHash (InvalidHashError é da 21.2+)."""
    import importlib

    import argon2.exceptions as exc
    monkeypatch.delattr(exc, "InvalidHashError", raising=False)
    mod = importlib.reload(security)
    try:
        assert mod._hasher is not None and mod.InvalidHashError is exc.InvalidHash
        assert mod.verify_password(mod.hash_password(PASSWORD), PASSWORD)[0]
    finally:
        monkeypatch.undo()
        importlib.reload(security)
