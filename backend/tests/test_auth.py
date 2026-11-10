from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from openmon.api import auth, authlog, security

PASSWORD = "Correta-Cavalo-Bateria-9"
NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


class FakeStore:
    """Mesma interface do PgAuthStore, em memória."""

    def __init__(self):
        self.users = {"admin": {"id": 1, "username": "admin", "display_name": "Admin", "email": None,
                                "auth_source": "local", "password_hash": security.hash_password(PASSWORD),
                                "is_active": True, "locked_until": None, "must_change_password": False,
                                "role": "global_admin", "role_name": "Administrador Global",
                                "scope": "global", "failed": 0, "last_login_at": None}}
        self.attempts = []
        self.sessions = {}

    async def settings(self):
        return {"auth.lockout": dict(auth.DEFAULT_LOCKOUT), "auth.session": dict(auth.DEFAULT_SESSION)}

    async def recent_failures(self, username, ip, minutes):
        mine = [a for a in self.attempts if a[0].lower() == username.lower()]
        last_ok = max((i for i, a in enumerate(mine) if a[2]), default=-1)
        return (sum(not a[2] for a in mine[last_ok + 1:]), sum(a[1] == ip and not a[2] for a in self.attempts))

    async def find_user(self, username):
        u = self.users.get(username.lower())
        return dict(u) if u else None

    async def record_attempt(self, username, ip, success, reason):
        self.attempts.append((username, ip, success, reason))

    async def register_failure(self, user_id, lockout):
        u = next(u for u in self.users.values() if u["id"] == user_id)
        u["failed"] += 1
        if u["failed"] >= lockout["max_failures"]:
            u["failed"], u["locked_until"] = 0, NOW() + timedelta(minutes=lockout["lock_minutes"])
            return True
        return False

    async def open_session(self, user, ip, ua, token_hash, csrf_hash, absolute_hours, new_hash):
        self.users[user["username"].lower()].update(failed=0, locked_until=None)
        exp = NOW() + timedelta(hours=absolute_hours)
        self.sessions[token_hash] = {"user": user, "csrf": csrf_hash, "exp": exp, "seen": NOW(), "revoked": False}
        return exp

    async def load_session(self, token_hash, idle_minutes):
        s = self.sessions.get(token_hash)
        if not s or s["revoked"] or s["exp"] < NOW() or s["seen"] < NOW() - timedelta(minutes=idle_minutes):
            return None
        s["seen"] = NOW()
        return {**s["user"], "csrf_token_hash": s["csrf"], "expires_at": s["exp"], "tenant_ids": []}

    async def revoke_session(self, token_hash, user, ip, ua):
        self.sessions[token_hash]["revoked"] = True


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
    assert body["user"]["role"] == "global_admin" and body["redirect"] == "/home.html"
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
