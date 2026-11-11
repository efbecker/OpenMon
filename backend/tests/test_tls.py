"""Domínio & HTTPS: validação do certificado, API (banco + fila) e o openmon-tls (root) com Apache simulado."""
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openmon import tlscert

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, names, issuer=None, issuer_key=None, ca=False, days=(-1, 200)):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(_name(cn))
         .issuer_name(issuer.subject if issuer else _name(cn)).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW + timedelta(days=days[0])).not_valid_after(NOW + timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    cert = b.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


def kpem(k, password=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc).decode()


@pytest.fixture(scope="module")
def pki():
    root, root_key = make_cert("Teste Root CA", None, ca=True, days=(-10, 3000))
    inter, inter_key = make_cert("Teste GCC R46 CA 2025", None, issuer=root, issuer_key=root_key, ca=True)
    leaf, leaf_key = make_cert("*.armazem.cloud", ["*.armazem.cloud", "armazem.cloud"], issuer=inter,
                               issuer_key=inter_key)
    return {"root": root, "inter": inter, "leaf": leaf, "key": leaf_key, "inter_key": inter_key}


def test_validate_fullchain_wildcard_and_order(pki):
    # fullchain fora de ordem (intermediária antes) + a raiz enviada como "cadeia"
    v = tlscert.validate("OpenMon.Armazem.Cloud.", pem(pki["inter"]) + pem(pki["leaf"]), kpem(pki["key"]),
                         pem(pki["root"]))
    assert v["domain"] == "openmon.armazem.cloud" and v["chain_count"] == 3 and v["warning"] is None
    first = x509.load_pem_x509_certificates(v["fullchain"].encode())
    assert [c.subject for c in first] == [pki["leaf"].subject, pki["inter"].subject, pki["root"].subject]
    assert v["info"]["issuer"] == "Teste GCC R46 CA 2025" and v["info"]["names"] == ["*.armazem.cloud", "armazem.cloud"]
    assert len(v["info"]["sha256"].split(":")) == 32 and 190 <= v["info"]["days_left"] <= 200
    assert "BEGIN PRIVATE KEY" in v["key"]
    # Só o certificado (sem intermediária): aceita, com aviso
    assert tlscert.validate("armazem.cloud", pem(pki["leaf"]), kpem(pki["key"]))["warning"]


@pytest.mark.parametrize("domain,cert,key,msg", [
    ("a.b.armazem.cloud", "leaf", "key", "não cobre"),          # curinga cobre um nível só
    ("outro.com.br", "leaf", "key", "não cobre"),
    ("openmon.armazem.cloud", "leaf", "inter_key", "não corresponde"),
    ("openmon", "leaf", "key", "Domínio inválido"),
])
def test_validate_rejects(pki, domain, cert, key, msg):
    with pytest.raises(tlscert.CertError, match=msg):
        tlscert.validate(domain, pem(pki[cert]), kpem(pki[key]))


def test_validate_rejects_expired_encrypted_and_garbage(pki):
    old, old_key = make_cert("x", ["openmon.armazem.cloud"], issuer=pki["inter"], issuer_key=pki["inter_key"],
                             days=(-400, -1))
    with pytest.raises(tlscert.CertError, match="venceu"):
        tlscert.validate("openmon.armazem.cloud", pem(old), kpem(old_key))
    with pytest.raises(tlscert.CertError, match="senha"):
        tlscert.validate("openmon.armazem.cloud", pem(pki["leaf"]), kpem(pki["key"], b"senha-123"))
    with pytest.raises(tlscert.CertError, match="PEM"):
        tlscert.validate("openmon.armazem.cloud", "MIIB...", kpem(pki["key"]))
    with pytest.raises(tlscert.CertError, match="chave privada"):
        tlscert.validate("openmon.armazem.cloud", pem(pki["leaf"]), "")


# ----------------------------------------------------------------- openmon-tls (root) com Apache simulado
def _fake_bin(path: Path, rc_file: Path, log: Path) -> None:
    path.write_text(f"#!/bin/sh\necho \"$(basename $0) $*\" >> {log}\nexit $(cat {rc_file} 2>/dev/null || echo 0)\n")
    path.chmod(0o755)


@pytest.fixture
def helper_env(tmp_path):
    etc = tmp_path / "etc"
    (etc / "certs").mkdir(parents=True)
    (etc / "private").mkdir()
    (etc / "conf-available").mkdir()
    (etc / "conf-enabled").mkdir()
    self_cert, _ = make_cert("openmon-vm1", ["openmon-vm1.local"])
    (etc / "certs" / "openmon.crt").write_text(pem(self_cert))
    log = tmp_path / "calls.log"
    rc = tmp_path / "configtest.rc"
    _fake_bin(tmp_path / "apache2ctl", rc, log)
    _fake_bin(tmp_path / "systemctl", tmp_path / "never", log)
    env = dict(os.environ, OPENMON_APP_DIR=str(ROOT / "backend"),
               OPENMON_TLS_REQUESTS=str(tmp_path / "req"), OPENMON_TLS_STATE=str(tmp_path / "state"),
               OPENMON_TLS_CERT=str(etc / "certs" / "openmon-domain.crt"),
               OPENMON_TLS_KEY=str(etc / "private" / "openmon-domain.key"),
               OPENMON_TLS_SELF_CERT=str(etc / "certs" / "openmon.crt"),
               OPENMON_TLS_CONF=str(etc / "conf-available" / "openmon-domain.conf"),
               OPENMON_TLS_CONF_ENABLED=str(etc / "conf-enabled" / "openmon-domain.conf"),
               OPENMON_TLS_APACHECTL=str(tmp_path / "apache2ctl"), OPENMON_TLS_SYSTEMCTL=str(tmp_path / "systemctl"),
               OPENMON_TLS_GROUP=str(os.getgid()), OPENMON_TLS_KEY_GROUP="root")
    (tmp_path / "req").mkdir()
    return {"env": env, "etc": etc, "log": log, "rc": rc, "tmp": tmp_path}


def run_helper(h, req=None):
    if req is not None:
        (h["tmp"] / "req" / "request.json").write_text(json.dumps(req))
    p = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "openmon-tls")], env=h["env"],
                       capture_output=True, text=True, timeout=60)
    status = json.loads((h["tmp"] / "state" / "status.json").read_text())
    return p, status


@pytest.mark.skipif(os.geteuid() != 0, reason="o openmon-tls grava como root (chown)")
def test_helper_apply_rollback_and_remove(pki, helper_env):
    h = helper_env
    p, st = run_helper(h)
    assert p.returncode == 0 and st["mode"] == "self-signed" and st["info"]["names"] == ["openmon-vm1.local"]

    v = tlscert.validate("openmon.armazem.cloud", pem(pki["leaf"]) + pem(pki["inter"]), kpem(pki["key"]))
    req = {"action": "apply", "id": "r1", "domain": v["domain"], "fullchain": v["fullchain"], "key": v["key"]}
    p, st = run_helper(h, req)
    assert p.returncode == 0, p.stdout + p.stderr
    assert st["mode"] == "custom" and st["domain"] == "openmon.armazem.cloud" and st["last"]["id"] == "r1"
    assert st["info"]["sha256"] == v["info"]["sha256"] and st["info"]["chain_count"] == 2
    conf = (h["etc"] / "conf-available" / "openmon-domain.conf").read_text()
    assert "Define OPENMON_HTTPS_DOMAIN" in conf and "Define OPENMON_FQDN openmon.armazem.cloud" in conf
    assert (h["etc"] / "conf-enabled" / "openmon-domain.conf").is_symlink()
    assert oct((h["etc"] / "private" / "openmon-domain.key").stat().st_mode & 0o777) == "0o640"
    assert "apache2ctl configtest" in h["log"].read_text() and "systemctl reload apache2" in h["log"].read_text()
    assert not (h["tmp"] / "req" / "request.json").exists()

    # configtest recusa: volta exatamente ao certificado anterior
    other, other_key = make_cert("app.armazem.cloud", ["app.armazem.cloud"], issuer=pki["inter"],
                                 issuer_key=pki["inter_key"])
    h["rc"].write_text("1")
    p, st = run_helper(h, {"action": "apply", "id": "r2", "domain": "app.armazem.cloud",
                           "fullchain": pem(other), "key": kpem(other_key)})
    assert p.returncode == 1 and st["last"]["ok"] is False and "recusada" in st["last"]["message"]
    assert st["domain"] == "openmon.armazem.cloud" and st["info"]["sha256"] == v["info"]["sha256"]
    h["rc"].write_text("0")

    # Pedido inválido (chave de outro certificado) nem chega ao Apache
    p, st = run_helper(h, {"action": "apply", "id": "r3", "domain": "openmon.armazem.cloud",
                           "fullchain": v["fullchain"], "key": kpem(other_key)})
    assert st["last"]["ok"] is False and "não corresponde" in st["last"]["message"]

    p, st = run_helper(h, {"action": "remove", "id": "r4"})
    assert p.returncode == 0 and st["mode"] == "self-signed" and st["last"]["ok"]
    assert not (h["etc"] / "conf-enabled" / "openmon-domain.conf").exists()
    assert not (h["etc"] / "private" / "openmon-domain.key").exists()

    p, st = run_helper(h, {"action": "rm -rf /"})
    assert st["last"]["ok"] is False and "inválida" in st["last"]["message"]


# ----------------------------------------------------------------- API (banco real)
from pgsupport import requires_pg, sql  # noqa: E402
from test_admin_tenants import client, database, h, login  # noqa: E402,F401


@requires_pg
def test_api_upload_reapply_remove_and_reinstall(pki, client, tmp_path, monkeypatch):
    from openmon import vault
    from openmon.api import admin_tls
    keyfile = tmp_path / "master.key"
    keyfile.write_bytes(os.urandom(32))
    monkeypatch.setenv("OPENMON_MASTER_KEY_FILE", str(keyfile))
    monkeypatch.setenv("OPENMON_TLS_REQUESTS", str(tmp_path / "req"))
    monkeypatch.setenv("OPENMON_TLS_STATE", str(tmp_path / "state"))
    vault.reset()
    sql("DELETE FROM credentials")
    sql("DELETE FROM vault_keys")
    csrf, _ = login(client)
    req_file = tmp_path / "req" / "request.json"

    body = {"domain": "openmon.armazem.cloud", "certificate": pem(pki["leaf"]), "private_key": kpem(pki["key"]),
            "chain": pem(pki["inter"])}
    r = client.post("/api/admin/tls", json={**body, "domain": "openmon.outro.com"}, headers=h(csrf))
    assert r.status_code == 422 and "não cobre" in r.json()["detail"]
    r = client.post("/api/admin/tls", json=body, headers=h(csrf))
    assert r.status_code == 200, r.text
    assert r.json()["info"]["issuer"] == "Teste GCC R46 CA 2025" and r.json()["chain_count"] == 2
    q = json.loads(req_file.read_text())
    assert q["action"] == "apply" and q["id"] == r.json()["request_id"] and "PRIVATE KEY" in q["key"]
    assert oct(req_file.stat().st_mode & 0o777) == "0o600"
    # No banco: certificado nos parâmetros, chave só cifrada
    cred = sql("SELECT kind, username, params, ciphertext FROM credentials WHERE name = 'tls:https'")[0]
    assert cred[0] == "generic" and cred[1] == "openmon.armazem.cloud" and "BEGIN CERTIFICATE" in cred[2]["fullchain"]
    assert b"PRIVATE KEY" not in bytes(cred[3])
    g = client.get("/api/admin/tls").json()
    assert g["pending"] and g["stored"]["domain"] == "openmon.armazem.cloud" and g["stored"]["uploaded_by"] == "admin"

    # Renovação só com o certificado: usa a chave guardada
    req_file.unlink()
    r = client.post("/api/admin/tls", json={**body, "private_key": None}, headers=h(csrf))
    assert r.status_code == 200 and json.loads(req_file.read_text())["key"] == q["key"]

    # Reinstalação: Apache no autoassinado e o banco com o certificado -> reaplica sozinho
    req_file.unlink()
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "state" / "status.json").write_text(json.dumps({"mode": "self-signed", "info": None, "last": None}))

    rid = client.portal.call(admin_tls.reapply_if_missing)
    assert rid and json.loads(req_file.read_text())["domain"] == "openmon.armazem.cloud"
    # Já ativo com o mesmo certificado: não faz nada
    req_file.unlink()
    info = tlscert.info_from_pem(cred[2]["fullchain"])
    (tmp_path / "state" / "status.json").write_text(json.dumps(
        {"mode": "custom", "domain": "openmon.armazem.cloud", "info": info, "last": {"ok": True}}))
    assert client.portal.call(admin_tls.reapply_if_missing) is None and not req_file.exists()

    assert client.post("/api/admin/tls/reapply", headers=h(csrf)).status_code == 200
    assert json.loads(req_file.read_text())["action"] == "apply"
    assert client.delete("/api/admin/tls", headers=h(csrf)).status_code == 200
    assert json.loads(req_file.read_text())["action"] == "remove"
    assert sql("SELECT count(*) FROM credentials WHERE name = 'tls:https'")[0][0] == 0
    assert [a[0] for a in sql("SELECT action FROM audit_log WHERE action LIKE 'tls.%%' ORDER BY time")] == \
        ["tls.upload", "tls.upload", "tls.reapply", "tls.remove"]
    vault.reset()
