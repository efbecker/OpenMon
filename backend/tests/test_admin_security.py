import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from openmon.api import admin_security, auth, authlog
from tests_support import FakeStore, PASSWORD  # noqa: F401  (ver conftest)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    for name, sub in (("OPENMON_STATE_DIR", "state"), ("OPENMON_LOG_DIR", "log"), ("OPENMON_DB_CONFIG_DIR", "etc")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(name, str(tmp_path / sub))
    (tmp_path / "state" / "fail2ban").mkdir()
    (tmp_path / "state" / "fail2ban-requests").mkdir()
    authlog.reset()
    store = FakeStore()
    monkeypatch.setattr(auth, "store", store)

    async def logins(hours=24):
        return [{"ip": "198.51.100.21", "attempts": 6, "successes": 0, "failures": 6,
                 "last_attempt": "2026-11-10T14:00:00+00:00", "usernames": ["admin"]}]
    monkeypatch.setattr(admin_security, "login_summary", logins)

    async def no_audit(*a, **k):
        return None
    monkeypatch.setattr(admin_security, "_audit", no_audit)
    from openmon.api.main import app
    with TestClient(app, base_url="https://testserver") as c:
        c.tmp, c.store = tmp_path, store
        yield c
    authlog.reset()


def login(c, username="admin"):
    return c.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()["csrf_token"]


def write_status(c, **over):
    status = {"updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "fail2ban_running": True,
              "jails": {"openmon-auth": {"total_banned": 3, "currently_failed": 1}},
              "bans": [{"ip": "198.51.100.21", "jail": "openmon-auth", "banned_at": "x", "expires_at": "y", "permanent": False}],
              "access": [{"ip": "198.51.100.20", "requests": 10, "errors_4xx": 0, "errors_5xx": 0, "first_seen": "a",
                          "last_seen": "b", "last_request": "GET / HTTP/1.1", "user_agent": "UA"}],
              "history": []}
    status.update(over)
    (c.tmp / "state" / "fail2ban" / "status.json").write_text(json.dumps(status))


def test_requires_login_and_admin_role(client):
    assert client.get("/api/admin/security/overview").status_code == 401
    client.store.users["operador"] = {**client.store.users["admin"], "id": 2, "username": "operador", "role": "operator"}
    login(client, "operador")
    assert client.get("/api/admin/security/overview").status_code == 403


def test_overview_merges_access_logins_and_bans(client):
    login(client)
    write_status(client)
    d = client.get("/api/admin/security/overview").json()
    assert d["bridge_ok"] and d["fail2ban_running"]
    by_ip = {r["ip"]: r for r in d["ips"]}
    assert by_ip["198.51.100.21"]["failures"] == 6 and by_ip["198.51.100.21"]["banned_in"] == ["openmon-auth"]
    assert by_ip["198.51.100.20"]["requests"] == 10 and by_ip["198.51.100.20"]["banned_in"] == []
    assert d["ips"][0]["ip"] == "198.51.100.21"  # mais falhas primeiro


def test_stale_bridge_is_reported(client):
    login(client)
    write_status(client, updated_at="2020-01-01T00:00:00Z")
    assert client.get("/api/admin/security/overview").json()["bridge_ok"] is False


def test_ban_writes_validated_request_and_needs_csrf(client):
    csrf = login(client)
    assert client.post("/api/admin/security/ban", json={"ip": "203.0.113.50"}).status_code == 403
    r = client.post("/api/admin/security/ban", json={"ip": "203.0.113.50", "reason": "varredura"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 202
    files = list((client.tmp / "state" / "fail2ban-requests").glob("*.json"))
    assert len(files) == 1 and oct(files[0].stat().st_mode & 0o777) == "0o600"
    assert json.loads(files[0].read_text()) == {"action": "ban", "ip": "203.0.113.50", "by": "admin", "reason": "varredura"}
    assert client.get("/api/admin/security/overview").json()["pending"] == [{"action": "ban", "ip": "203.0.113.50"}]


@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "1.2.3", "1.2.3.4; reboot", "::1"])
def test_ban_rejects_bad_ips(client, ip):
    csrf = login(client)
    r = client.post("/api/admin/security/ban", json={"ip": ip}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 422
    assert not list((client.tmp / "state" / "fail2ban-requests").iterdir())


def test_cannot_ban_yourself(client, monkeypatch):
    csrf = login(client)
    monkeypatch.setattr(admin_security.security, "client_ip", lambda req: "198.51.100.99")
    r = client.post("/api/admin/security/ban", json={"ip": "198.51.100.99"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 422 and "próprio IP" in r.json()["detail"]


# -----------------------------------------------------------------------------
# openmon-fail2ban (ponte root) com um fail2ban-client simulado
# -----------------------------------------------------------------------------
FAKE_CLIENT = r'''#!/usr/bin/env python3
import json, sys, os
db = os.environ["FAKE_DB"]
state = json.load(open(db)) if os.path.exists(db) else {"openmon-auth": [], "openmon-manual": []}
a = sys.argv[1:]
open(os.environ["FAKE_LOG"], "a").write(json.dumps(a) + "\n")
if a == ["ping"]: print("Server replied: pong")
elif a[0] == "get" and a[2] == "banip":
    for ip in state[a[1]]:
        print(f"{ip} \t2026-11-10 14:43:40 + {-1 if a[1] == 'openmon-manual' else 3600} = 2026-11-10 15:43:40")
elif a[0] == "status": print(f"Currently failed:\t0\nTotal failed:\t2\nCurrently banned:\t{len(state[a[1]])}\nTotal banned:\t4")
elif a[0] == "set" and a[2] == "banip": state[a[1]] = sorted(set(state[a[1]]) | set(a[3:])); print(len(a[3:]))
elif a[0] == "unban":
    for j in state: state[j] = [i for i in state[j] if i not in a[1:]]
    print(1)
json.dump(state, open(db, "w"))
'''


def test_bridge_end_to_end_with_fake_client(tmp_path):
    client = tmp_path / "fail2ban-client"
    client.write_text(FAKE_CLIENT)
    client.chmod(0o755)
    req, st = tmp_path / "req", tmp_path / "st"
    req.mkdir()
    now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    (tmp_path / "access.log").write_text(
        f'198.51.100.20 - - [{now}] "GET /login.html HTTP/1.1" 200 12 "-" "Mozilla"\n'
        f'198.51.100.20 - - [{now}] "POST /api/auth/login HTTP/1.1" 401 12 "-" "Mozilla"\n'
        'linha quebrada\n')
    (req / "1.json").write_text('{"action":"ban","ip":"203.0.113.50","by":"admin","reason":"teste"}')
    (req / "2.json").write_text('{"action":"ban","ip":"10.0.0.1; rm -rf /","by":"x"}')
    (req / "3.json").write_text("x" * 5000)
    os.symlink("/etc/passwd", req / "4.json")
    env = {**os.environ, "OPENMON_F2B_REQUESTS": str(req), "OPENMON_F2B_STATE": str(st),
           "OPENMON_F2B_ACCESS_LOGS": str(tmp_path / "access.log"), "OPENMON_F2B_CLIENT": str(client),
           "OPENMON_F2B_GROUP": "root", "FAKE_DB": str(tmp_path / "db.json"), "FAKE_LOG": str(tmp_path / "calls.log")}
    run = lambda: subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "openmon-fail2ban")], env=env, check=True)  # noqa: E731
    run()
    assert list(req.iterdir()) == []
    status = json.loads((st / "status.json").read_text())
    assert [b["ip"] for b in status["bans"]] == ["203.0.113.50"] and status["bans"][0]["permanent"]
    assert status["bans"][0]["reason"] == "teste"
    assert status["access"][0]["requests"] == 2 and status["access"][0]["errors_4xx"] == 1
    assert [h["ok"] for h in status["history"]] == [False, True]
    calls = (tmp_path / "calls.log").read_text()
    assert "rm -rf" not in calls and "passwd" not in calls

    # Fail2ban reiniciou e perdeu o banimento: a ponte reaplica
    (tmp_path / "db.json").write_text(json.dumps({"openmon-auth": [], "openmon-manual": []}))
    run()
    assert json.loads((tmp_path / "db.json").read_text())["openmon-manual"] == ["203.0.113.50"]

    (req / "5.json").write_text('{"action":"unban","ip":"203.0.113.50","by":"admin"}')
    run()
    assert json.loads((st / "manual.json").read_text()) == {}
    assert json.loads((st / "status.json").read_text())["bans"] == []
