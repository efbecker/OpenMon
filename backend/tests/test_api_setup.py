import json
import time

import pytest
from fastapi.testclient import TestClient

from openmon.api import authlog, setup
from openmon.deploy import provisioner
from openmon.deploy.ssh import HostKey

TOKEN = "tok-" + "a" * 40
FPR = "SHA256:" + "A" * 43


@pytest.fixture()
def client(tmp_path, monkeypatch):
    for name, sub in (("OPENMON_STATE_DIR", "state"), ("OPENMON_LOG_DIR", "log"), ("OPENMON_DB_CONFIG_DIR", "etc/database")):
        (tmp_path / sub).mkdir(parents=True)
        monkeypatch.setenv(name, str(tmp_path / sub))
    (tmp_path / "state" / "setup.token").write_text(TOKEN + "\n")
    authlog.reset()
    setup._failures.clear()
    setup.job.__init__()
    from openmon.api.main import app
    with TestClient(app) as c:
        c.tmp = tmp_path
        yield c
    authlog.reset()


H = {"X-Setup-Token": TOKEN}
FORM = {"host": "10.0.0.20", "port": 22, "username": "admin", "password": "segredo"}


def test_status_is_public(client):
    r = client.get("/api/setup/status")
    assert r.json() == {"setup_open": True, "db_provisioned": False, "admin_created": False,
                        "deploy_status": "idle"}


def test_token_required_and_logged_for_fail2ban(client):
    assert client.post("/api/setup/token/verify").status_code == 401
    assert client.post("/api/setup/token/verify", headers={"X-Setup-Token": "errado"}).status_code == 401
    assert client.post("/api/setup/token/verify", headers=H).json() == {"ok": True}
    line = (client.tmp / "log" / "auth.log").read_text().splitlines()[0]
    assert line.startswith('{"ts":"') and '"event":"auth.failure","ip":"testclient"' in line


def test_rate_limit(client):
    for _ in range(setup.MAX_FAILURES):
        client.post("/api/setup/token/verify", headers={"X-Setup-Token": "x"})
    assert client.post("/api/setup/token/verify", headers=H).status_code == 429


def test_closed_when_token_removed(client):
    (client.tmp / "state" / "setup.token").unlink()
    assert client.post("/api/setup/token/verify", headers=H).status_code == 403
    assert client.get("/api/setup/status").json()["setup_open"] is False


def test_ssh_test_fingerprint_stage_sends_no_secret(client, monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "fetch_host_key", lambda h, p: calls.append((h, p)) or HostKey("ssh-ed25519", FPR, "AAAA"))
    monkeypatch.setattr(provisioner, "probe_target", lambda t: pytest.fail("não deveria autenticar"))
    r = client.post("/api/setup/database/ssh-test", headers=H, json={**FORM, "password": ""})
    assert r.json() == {"stage": "fingerprint", "key_type": "ssh-ed25519", "fingerprint": FPR}
    assert calls == [("10.0.0.20", 22)]


def test_ssh_test_verified_stage(client, monkeypatch):
    seen = {}

    def probe(target):
        seen["t"] = target
        return {"os": "Debian GNU/Linux 13 (trixie)", "cpus": 4}
    monkeypatch.setattr(provisioner, "probe_target", probe)
    r = client.post("/api/setup/database/ssh-test", headers=H, json={**FORM, "fingerprint": FPR})
    assert r.status_code == 200 and r.json()["stage"] == "verified"
    assert seen["t"].host_fingerprint == FPR and seen["t"].password == "segredo"


@pytest.mark.parametrize("field,value", [("host", "10.0.0.20;reboot"), ("username", "Admin$"), ("fingerprint", "md5:xx")])
def test_input_validation(client, field, value):
    r = client.post("/api/setup/database/ssh-test", headers=H, json={**FORM, field: value})
    assert r.status_code == 422


def test_deploy_requires_fingerprint(client):
    r = client.post("/api/setup/database/deploy", headers=H, json={**FORM, "frontend_address": "10.0.0.10"})
    assert r.status_code == 422


def test_deploy_flow_keeps_wizard_open_for_admin_step(client, monkeypatch):
    def fake_run(self):
        self._emit("step", "[1/9] Validando", 12)
        assert self.req.frontend_address == "10.0.0.10/32"
        assert str(self.req.config_dir).endswith("etc/database")
        return provisioner.DeployResult(success=True, host="10.0.0.20", port=5432,
                                        info={"timescaledb_version": "2.22.0"}, app_password="x" * 32)
    monkeypatch.setattr(provisioner.DatabaseDeployer, "run", fake_run)
    body = {**FORM, "fingerprint": FPR, "frontend_address": "10.0.0.10"}
    assert client.post("/api/setup/database/deploy", headers=H, json=body).status_code == 202
    for _ in range(50):
        snap = client.get("/api/setup/database/deploy", headers=H).json()
        if snap["status"] != "running":
            break
        time.sleep(0.05)
    assert snap["status"] == "success"
    assert snap["events"][0]["message"] == "[1/9] Validando"
    assert "x" * 32 not in json.dumps(snap)  # senha do banco nunca volta para o navegador
    # o token continua valendo para a etapa seguinte (criar o administrador)
    assert (client.tmp / "state" / "setup.token").exists()
    assert client.get("/api/setup/status").json()["admin_created"] is False


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


# -----------------------------------------------------------------------------
# Primeiro administrador
# -----------------------------------------------------------------------------
ADMIN = {"username": "admin", "password": "Correta-Cavalo-Bateria-9", "password_confirm": "Correta-Cavalo-Bateria-9"}


@pytest.fixture()
def provisioned(client, monkeypatch):
    (client.tmp / "etc" / "database" / "database.conf").write_text("[database]\n")
    created = []

    async def fake_create(form, password_hash, ip, ua):
        if created:
            return None
        created.append((form.username, password_hash))
        return 1

    async def fake_exists():
        return bool(created)
    monkeypatch.setattr(setup, "create_first_admin", fake_create)
    monkeypatch.setattr(setup, "users_exist", fake_exists)
    client.created = created
    return client


def test_admin_requires_database(client):
    assert client.post("/api/setup/admin", headers=H, json=ADMIN).status_code == 409


def test_admin_requires_token(provisioned):
    assert provisioned.post("/api/setup/admin", json=ADMIN).status_code == 401


@pytest.mark.parametrize("change,msg", [
    ({"password": "curta", "password_confirm": "curta"}, "12"),
    ({"password_confirm": "outra-coisa-qualquer"}, "não conferem"),
    ({"password": "admin-admin-123", "password_confirm": "admin-admin-123"}, "nome de usuário"),
])
def test_admin_password_policy(provisioned, change, msg):
    r = provisioned.post("/api/setup/admin", headers=H, json={**ADMIN, **change})
    assert r.status_code == 422 and msg in r.json()["detail"]
    assert provisioned.created == []


def test_admin_creation_closes_setup(provisioned):
    assert provisioned.get("/api/setup/admin", headers=H).json() == {"needed": True}
    r = provisioned.post("/api/setup/admin", headers=H, json=ADMIN)
    assert r.status_code == 201 and r.json()["redirect"] == "/login.html"
    username, password_hash = provisioned.created[0]
    assert username == "admin" and password_hash.startswith("$argon2id$")
    assert ADMIN["password"] not in password_hash
    st = provisioned.get("/api/setup/status").json()
    assert st["setup_open"] is False and st["admin_created"] is True
    assert not (provisioned.tmp / "state" / "setup.token").exists()
    # assistente fechado: nada mais aceita o token antigo
    assert provisioned.post("/api/setup/admin", headers=H, json=ADMIN).status_code == 403
    assert provisioned.post("/api/setup/database/ssh-test", headers=H, json=FORM).status_code == 403
    log = (provisioned.tmp / "log" / "auth.log").read_text()
    assert '"event":"setup.admin_created"' in log and ADMIN["password"] not in log


def test_finish_when_admin_already_exists(provisioned):
    assert provisioned.post("/api/setup/finish", headers=H).status_code == 409
    provisioned.created.append(("admin", "$argon2id$x"))
    assert provisioned.get("/api/setup/admin", headers=H).json() == {"needed": False}
    assert provisioned.post("/api/setup/admin", headers=H, json=ADMIN).status_code == 409
    assert provisioned.post("/api/setup/finish", headers=H).status_code == 200
    assert provisioned.get("/api/setup/status").json()["admin_created"] is True
