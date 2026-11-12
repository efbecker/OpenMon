"""Alertas: avaliação dos triggers, problemas, reconhecimento e envio (webhook, Telegram, e-mail)."""
import hashlib
import hmac
import json
import os

import httpx
import pytest

from openmon import scheduler, vault
from openmon.scheduler import notify

from pgsupport import requires_pg, sql
from test_admin_tenants import client, database, h, login, new_tenant, new_user, TEMP_PW  # noqa: F401

pytestmark = requires_pg
TOKEN = "123456789:AAH-telegram-token-de-teste-1234567890"


class Outbox:
    def __init__(self):
        self.http = []
        self.mail = []
        self.fail_webhook = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.http.append(request)
        if request.url.host == "api.telegram.org":
            assert request.url.path == f"/bot{TOKEN}/sendMessage"
            return httpx.Response(200, json={"ok": True})
        if self.fail_webhook:
            return httpx.Response(503, text="indisponível")
        return httpx.Response(204)


class FakeSMTP:
    box: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.tls = host, port, context is not None
        self.logged = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        self.tls = True

    def login(self, user, pw):
        self.logged = (user, pw)

    def send_message(self, msg):
        assert self.tls, "e-mail sem TLS"
        FakeSMTP.box.append((self.host, self.port, self.logged, msg))


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    path = tmp_path / "master.key"
    path.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(path))
    vault.reset()
    box = Outbox()
    FakeSMTP.box = box.mail
    monkeypatch.setattr(notify, "_transport", httpx.MockTransport(box.handler))
    monkeypatch.setattr(notify, "_smtp_factory", FakeSMTP)
    yield box
    vault.reset()


def tick(client):
    return client.portal.call(scheduler.tick)


def mk_asset(tenant_id, name, asset_type="vm", status="up", ext=None):
    return sql("INSERT INTO assets (tenant_id, asset_type, name, external_id, status, last_status_change_at) "
               "VALUES (%s, %s, %s, %s, %s, now() - interval '1 hour') RETURNING id",
               tenant_id, asset_type, name, ext or name, status)[0][0]


def metric(asset_id, tenant_id, metric_id, value, minutes_ago=1):
    sql("INSERT INTO metric_samples (time, tenant_id, asset_id, metric_id, value) "
        "VALUES (now() - make_interval(mins => %s), %s, %s, %s, %s)", minutes_ago, tenant_id, asset_id, metric_id,
        value)


def test_metric_trigger_hysteresis_channels_and_tenant_isolation(client, outbox):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf)
    beta = new_tenant(client, csrf, "beta", "Beta")
    vm_a = mk_asset(acme["id"], "acme-db01")
    vm_b = mk_asset(beta["id"], "beta-erp")
    for v in (95, 97, 99):
        metric(vm_a, acme["id"], 1, v)
    metric(vm_b, beta["id"], 1, 40)

    r = client.post("/api/alerts/channels", json={
        "name": "NOC webhook", "kind": "webhook", "secret": "segredo-hmac",
        "config": {"url": "https://hooks.empresa.local/openmon", "headers": {"X-Origem": "openmon"}}}, headers=h(csrf))
    assert r.status_code == 201, r.text
    hook = r.json()["id"]
    r = client.post("/api/alerts/channels", json={
        "name": "Telegram ACME", "kind": "telegram", "tenant_id": acme["id"], "secret": TOKEN,
        "config": {"chat_id": "-1001234567890"}}, headers=h(csrf))
    tg = r.json()["id"]
    r = client.post("/api/alerts/channels", json={
        "name": "E-mail Beta", "kind": "telegram", "tenant_id": beta["id"], "secret": TOKEN,
        "config": {"chat_id": "-1009999"}}, headers=h(csrf))
    tg_beta = r.json()["id"]
    assert "segredo" not in json.dumps(client.get("/api/alerts/channels").json())
    assert client.post("/api/alerts/channels", json={"name": "x", "kind": "webhook",
                                                     "config": {"url": "http://inseguro"}},
                       headers=h(csrf)).status_code == 422

    body = {"name": "CPU alta", "source": "metric", "metric_id": 1, "expression": "avg", "operator": ">",
            "threshold": 90, "recovery_threshold": 80, "window_seconds": 600, "severity": "high",
            "channel_ids": [hook, tg, tg_beta]}
    r = client.post("/api/alerts/triggers", json=body, headers=h(csrf))
    assert r.status_code == 201, r.text
    trig = r.json()["id"]

    out = tick(client)
    assert out["eval"]["opened"] == 1, out
    assert out["notify"]["sent"] == 2  # webhook (global) + Telegram da ACME; o da Beta não recebe problema da ACME
    hooks = [x for x in outbox.http if x.url.host == "hooks.empresa.local"]
    payload = json.loads(hooks[0].content)
    assert payload["event"] == "problem" and payload["asset"] == "acme-db01" and payload["tenant"] == "ACME S.A."
    ts = hooks[0].headers["x-openmon-timestamp"]
    expected = hmac.new(b"segredo-hmac", ts.encode() + b"." + hooks[0].content, hashlib.sha256).hexdigest()
    assert hooks[0].headers["x-openmon-signature"] == f"sha256={expected}"
    assert hooks[0].headers["x-origem"] == "openmon"
    tgm = json.loads([x for x in outbox.http if x.url.host == "api.telegram.org"][0].content)
    assert tgm["chat_id"] == "-1001234567890" and "acme-db01" in tgm["text"] and "parse_mode" not in tgm

    # Segunda rodada: nada novo (um problema aberto por trigger + ativo)
    assert tick(client)["eval"] == {"triggers": 1, "opened": 0, "resolved": 0}
    # Cai para 85: acima da recuperação (80), continua aberto; 70: resolve e avisa
    sql("DELETE FROM metric_samples")
    metric(vm_a, acme["id"], 1, 85)
    assert tick(client)["eval"]["resolved"] == 0
    sql("DELETE FROM metric_samples")
    metric(vm_a, acme["id"], 1, 70)
    out = tick(client)
    assert out["eval"]["resolved"] == 1 and out["notify"]["sent"] == 2
    assert json.loads([x for x in outbox.http if x.url.host == "hooks.empresa.local"][-1].content)["event"] == \
        "recovery"

    # Cliente vê só os problemas dele e não gerencia nada
    sql("DELETE FROM metric_samples")
    metric(vm_a, acme["id"], 1, 99)
    metric(vm_b, beta["id"], 1, 99)
    tick(client)
    new_user(client, csrf, "cli-beta", tenant_ids=[beta["id"]], must_change_password=False)
    ccsrf, _ = login(client, "cli-beta", TEMP_PW)
    probs = client.get("/api/alerts/problems").json()
    assert [p["asset_name"] for p in probs["problems"]] == ["beta-erp"] and not probs["can_ack"]
    assert client.get("/api/alerts/triggers").status_code == 403
    assert client.get("/api/alerts/channels").status_code == 403
    acme_problem = sql("SELECT id FROM alert_problems WHERE asset_id = %s AND status = 'problem'", vm_a)[0][0]
    assert client.post(f"/api/alerts/problems/{acme_problem}/ack", json={}, headers=h(ccsrf)).status_code == 403

    # Operador reconhece: avisa os canais com "reconhecido"
    csrf, _ = login(client)
    new_user(client, csrf, "noc", role="operator", must_change_password=False)
    ocsrf, _ = login(client, "noc", TEMP_PW)
    r = client.post(f"/api/alerts/problems/{acme_problem}/ack", json={"comment": "olhando"}, headers=h(ocsrf))
    assert r.status_code == 200
    assert client.post(f"/api/alerts/problems/{acme_problem}/ack", json={}, headers=h(ocsrf)).status_code == 409
    out = tick(client)
    acks = [json.loads(x.content) for x in outbox.http if x.url.host == "hooks.empresa.local"]
    assert acks[-1]["event"] == "ack" and acks[-1]["comment"] == "olhando"

    # Desligar o alerta fecha os problemas dele
    csrf, _ = login(client)
    body["is_enabled"] = False
    assert client.put(f"/api/alerts/triggers/{trig}", json=body, headers=h(csrf)).status_code == 200
    assert sql("SELECT count(*) FROM alert_problems WHERE status = 'problem'")[0][0] == 0


def test_availability_backup_integration_and_storage(client, outbox):
    csrf, _ = login(client)
    acme = new_tenant(client, csrf, backup_sla_hours=24)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    sw = mk_asset(provider, "core-sw", "network_switch", status="down")
    mk_asset(acme["id"], "vm-desligada", status="powered_off")
    fresh = mk_asset(acme["id"], "caiu-agora", status="down")
    sql("UPDATE assets SET last_status_change_at = now() WHERE id = %s", fresh)
    ds = mk_asset(provider, "ds01", "datastore")
    metric(ds, provider, 50, 1000)
    metric(ds, provider, 52, 950)
    iid = sql("INSERT INTO integrations (tenant_id, kind, name, endpoint, last_status, last_error) "
              "VALUES (%s, 'snmp', 'sw-x', '10.0.0.9', 'error', 'timeout') RETURNING id", provider)[0][0]
    job = sql("INSERT INTO backup_jobs (tenant_id, integration_id, external_id, name, last_result, last_success_at) "
              "VALUES (%s, %s, 'j1', 'ACME - Diário', 'success', now() - interval '30 hours') RETURNING id",
              acme["id"], iid)[0][0]
    mk_asset(acme["id"], "ACME - Diário", "other", ext="job:j1")
    sql("UPDATE assets SET integration_id = %s, attributes = jsonb_build_object('backup_job_id', %s) "
        "WHERE external_id = 'job:j1'", iid, job)

    r = client.post("/api/alerts/triggers/recommended", headers=h(csrf))
    assert len(r.json()["created"]) == 8
    assert client.post("/api/alerts/triggers/recommended", headers=h(csrf)).json()["created"] == []
    tick(client)
    msgs = {r[0]: r[1] for r in sql("SELECT a.name, p.message FROM alert_problems p "
                                    "LEFT JOIN assets a ON a.id = p.asset_id WHERE p.status = 'problem'")}
    assert "core-sw" in msgs and "vm-desligada" not in msgs and "caiu-agora" not in msgs
    assert "SLA 24 h" in msgs["ACME - Diário"] and "há 30 h" in msgs["ACME - Diário"]
    assert "95.0%" in msgs["ds01"]
    assert "sw-x: timeout" in msgs[None]

    # Volta: o switch responde, o backup roda, a integração se recupera
    sql("UPDATE assets SET status = 'up' WHERE id = %s", sw)
    sql("UPDATE backup_jobs SET last_success_at = now()")
    sql("UPDATE integrations SET last_status = 'ok'")
    out = tick(client)
    assert out["eval"]["resolved"] == 3, out
    left = [r[0] for r in sql("SELECT message FROM alert_problems WHERE status = 'problem'")]
    assert len(left) == 1 and "ds01" in left[0]

    # O cliente ACME vê o problema do backup dele (resolvido), não os do datacenter
    new_user(client, csrf, "cli-acme", tenant_ids=[acme["id"]], must_change_password=False)
    login(client, "cli-acme", TEMP_PW)
    seen = client.get("/api/alerts/problems?status=all").json()["problems"]
    assert [p["asset_name"] for p in seen] == ["ACME - Diário"]


def test_retries_email_and_channel_test(client, outbox):
    csrf, _ = login(client)
    provider = sql("SELECT id FROM tenants WHERE is_provider")[0][0]
    vm = mk_asset(provider, "srv01", status="down")
    r = client.post("/api/alerts/channels", json={
        "name": "E-mail NOC", "kind": "email", "username": "alertas@empresa.com.br", "secret": "Senha-smtp-1",
        "config": {"host": "smtp.empresa.com.br", "port": 587, "security": "starttls",
                   "from": "OpenMon <alertas@empresa.com.br>".split("<")[1].rstrip(">"),
                   "to": ["noc@empresa.com.br", "plantao@empresa.com.br"]}}, headers=h(csrf))
    assert r.status_code == 201, r.text
    mail = r.json()["id"]
    hook = client.post("/api/alerts/channels", json={
        "name": "Hook", "kind": "webhook", "config": {"url": "https://hooks.empresa.local/x"}},
        headers=h(csrf)).json()["id"]
    plain = client.post("/api/alerts/channels", json={
        "name": "sem tls", "kind": "email", "config": {"host": "smtp.x.com", "security": "none",
                                                       "from": "a@x.com", "to": ["b@x.com"]}}, headers=h(csrf))
    assert plain.status_code == 422

    t = client.post("/api/alerts/channels/test", json={
        "channel_id": mail, "name": "E-mail NOC", "kind": "email", "username": "alertas@empresa.com.br",
        "config": {"host": "smtp.empresa.com.br", "port": 587, "security": "starttls",
                   "from": "alertas@empresa.com.br", "to": ["noc@empresa.com.br"]}}, headers=h(csrf)).json()
    assert t == {"ok": True, "error": None}
    host, port, logged, msg = outbox.mail[-1]
    assert (host, port, logged) == ("smtp.empresa.com.br", 587, ("alertas@empresa.com.br", "Senha-smtp-1"))
    assert "TESTE" in msg["Subject"]

    client.post("/api/alerts/triggers", json={"name": "Fora", "source": "availability", "operator": "<",
                                              "threshold": 1, "window_seconds": 60, "severity": "disaster",
                                              "channel_ids": [mail, hook]}, headers=h(csrf))
    outbox.fail_webhook = True
    out = tick(client)
    assert out["notify"] == {"sent": 1, "failed": 0, "retry": 1}
    assert "PROBLEMA [Desastre] srv01" in outbox.mail[-1][3]["Subject"]
    d = sql("SELECT status, attempts, last_error FROM notification_deliveries WHERE channel_id = %s", hook)[0]
    assert d[0] == "queued" and d[1] == 1 and "503" in d[2]
    # Espera crescente: só tenta de novo depois de 1 min; após 5 tentativas desiste
    assert tick(client)["notify"]["retry"] == 0
    for _ in range(4):
        sql("UPDATE notification_deliveries SET created_at = created_at - interval '1 hour' WHERE channel_id = %s",
            hook)
        tick(client)
    assert sql("SELECT status, attempts FROM notification_deliveries WHERE channel_id = %s", hook)[0] == \
        ("failed", 5)
    assert vm
