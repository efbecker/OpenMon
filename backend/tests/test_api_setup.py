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
    assert r.json() == {"setup_open": True, "db_provisioned": False, "deploy_status": "idle"}


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


def test_deploy_flow_closes_wizard(client, monkeypatch):
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
    assert not (client.tmp / "state" / "setup.token").exists()
    # quem acompanhava ainda lê o resultado; todo o resto fica fechado
    assert client.get("/api/setup/database/deploy", headers=H).status_code == 200
    assert client.post("/api/setup/database/deploy", headers=H, json=body).status_code == 403


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"
