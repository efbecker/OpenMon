import shlex
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from openmon.deploy import provisioner as prov
from openmon.deploy.ssh import SshTarget

PREFLIGHT_OK = {
    "OS_ID": "debian", "OS_VERSION_ID": "13", "OS_CODENAME": "trixie", "OS_PRETTY": "Debian GNU/Linux 13 (trixie)",
    "ARCH": "amd64", "CPUS": "4", "MEM_KB": str(8 * 1024**2), "DISK_BYTES": str(200 * 1024**3),
    "ROTATIONAL": "0", "SUDO": "password", "HOSTNAME": "db01.dc.local", "IPS": "10.0.0.20 fe80::1",
}


def test_normalize_cidr():
    assert prov.normalize_cidr("10.0.0.10") == "10.0.0.10/32"
    assert prov.normalize_cidr("10.0.0.10/24") == "10.0.0.0/24"
    assert prov.normalize_cidr("2001:db8::1") == "2001:db8::1/128"
    for bad in ("0.0.0.0/0", "10.0.0.1; rm -rf /", "abc"):
        with pytest.raises(prov.DeployError):
            prov.normalize_cidr(bad)


def test_validate_host_rejects_injection():
    assert prov.validate_host("db01.dc.local") == "db01.dc.local"
    for bad in ("db01;reboot", "$(id)", "a b", ""):
        with pytest.raises(prov.DeployError):
            prov.validate_host(bad)


@pytest.mark.parametrize("change,msg", [
    ({"OS_ID": "ubuntu"}, "Debian"),
    ({"OS_VERSION_ID": "12"}, "não suportado"),
    ({"ARCH": "i386"}, "arquitetura"),
    ({"SUDO": "missing"}, "sudo"),
])
def test_preflight_rejections(change, msg):
    with pytest.raises(prov.DeployError, match=msg):
        prov.check_preflight({**PREFLIGHT_OK, **change})


def test_preflight_testing_codename_without_version():
    prov.check_preflight({**PREFLIGHT_OK, "OS_VERSION_ID": "", "OS_CODENAME": "forky"})


def test_certificate_sans():
    cn, sans = prov.certificate_sans("10.0.0.20", PREFLIGHT_OK)
    assert cn == "10.0.0.20"
    assert sans == "IP:10.0.0.20,DNS:db01.dc.local,DNS:localhost,IP:127.0.0.1"  # link-local ignorado


def test_params_are_shell_quoted(tmp_path):
    text = prov.render_params({"CERT_SANS": "IP:1.2.3.4,DNS:x", "WEIRD": "a'b $(id)"})
    script = tmp_path / "p.env"
    script.write_text(text)
    out = subprocess.run(["bash", "-c", f". {shlex.quote(str(script))}; printf '%s' \"$WEIRD\""],
                         capture_output=True, text=True, check=True).stdout
    assert out == "a'b $(id)"


def test_roles_sql_only_accepts_verifiers():
    with pytest.raises(prov.DeployError):
        prov.render_roles_sql("plaintext", "SCRAM-SHA-256$4096:a$b:c")


class FakeSession:
    """Simula a VM 2: devolve o preflight e reproduz a saída do provision_db.sh."""

    def __init__(self, target, remote_lines, exit_code=0):
        self.target, self.remote_lines, self.exit_code = target, remote_lines, exit_code
        self.uploaded = {}
        self.commands = []
        self.removed = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def run(self, command, timeout=60):
        return 0, "\n".join(f"{k}={v}" for k, v in PREFLIGHT_OK.items())

    def make_work_dir(self):
        return "/tmp/openmon-deploy.abc123"

    def upload_tree(self, files, remote_dir):
        self.uploaded = files

    def run_streaming(self, command, on_line, as_root=False, timeout=0):
        self.commands.append((command, as_root))
        for line in self.remote_lines:
            on_line(line)
        return self.exit_code

    def remove_work_dir(self, d):
        self.removed = d


REMOTE_OK = [
    "::step::1::9::Validando sistema operacional (Debian 13+)",
    "::info::os::Debian GNU/Linux 13 (trixie)",
    "Get:1 https://apt.postgresql.org ...",
    "::warn::impressão digital da chave TimescaleDB não fixada",
    "::step::5::9::Gerando certificados TLS",
    "::cert-begin::", "-----BEGIN CERTIFICATE-----", "MIIB", "-----END CERTIFICATE-----", "::cert-end::",
    "::step::9::9::Validando a instalação",
    "::info::server_version::17.6",
    "::info::timescaledb_version::2.22.0",
    "::done::",
]


def make_request(tmp_path, **kw):
    return prov.DeployRequest(
        ssh=SshTarget(host="10.0.0.20", username="admin", password="S3nh@-SSH!", host_fingerprint="SHA256:abc"),
        frontend_address="10.0.0.10", config_dir=tmp_path / "etc", validate_from_frontend=False, **kw)


def run_with_fake(monkeypatch, request, lines=REMOTE_OK, exit_code=0):
    holder = {}

    def factory(target):
        holder["s"] = FakeSession(target, lines, exit_code)
        return holder["s"]

    monkeypatch.setattr(prov, "SshSession", factory)
    events = []
    result = prov.DatabaseDeployer(request, events.append).run()
    return result, events, holder["s"]


def test_full_flow_with_fake_session(monkeypatch, tmp_path):
    result, events, session = run_with_fake(monkeypatch, make_request(tmp_path))
    assert result.success, result.error
    assert result.info["timescaledb_version"] == "2.22.0"
    assert result.ca_cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert result.warnings == ["impressão digital da chave TimescaleDB não fixada"]
    assert session.commands == [("bash /tmp/openmon-deploy.abc123/provision_db.sh /tmp/openmon-deploy.abc123", True)]
    assert session.removed == "/tmp/openmon-deploy.abc123"

    files = session.uploaded
    assert {"provision_db.sh", "params.env", "tuning.conf", "roles.sql", "sql/manifest", "sql/0000_bootstrap.sql"} <= set(files)
    params = files["params.env"].decode()
    assert "ALLOW_CIDR=10.0.0.10/32" in params
    assert "LISTEN_ADDRESSES=localhost,10.0.0.20" in params
    # Senhas em texto puro nunca saem da VM 1
    everything = b"".join(files.values()).decode()
    assert result.app_password not in everything and result.owner_password not in everything
    assert "SCRAM-SHA-256$4096:" in files["roles.sql"].decode()

    conf = (tmp_path / "etc" / "database.conf")
    assert conf.stat().st_mode & 0o777 == 0o600
    assert f"password = {result.app_password}" in conf.read_text()
    assert "sslmode = verify-full" in conf.read_text()
    assert (tmp_path / "etc" / "database-owner.conf").stat().st_mode & 0o777 == 0o600

    percents = [e.percent for e in events]
    assert percents == sorted(percents) and percents[-1] == 100
    for e in events:
        assert "S3nh@-SSH!" not in e.message


def test_no_firewall_management(monkeypatch, tmp_path):
    _, _, session = run_with_fake(monkeypatch, make_request(tmp_path))
    params = session.uploaded["params.env"].decode()
    assert "SSH_ALLOW" not in params and "FIREWALL" not in params
    script = session.uploaded["provision_db.sh"].decode()
    assert "nft -f" not in script and "TOTAL_STEPS=8" in script


def test_remote_failure_is_reported(monkeypatch, tmp_path):
    lines = ["::step::4::9::Instalando", "::error::pacote timescaledb-2-postgresql-17 indisponível"]
    result, events, session = run_with_fake(monkeypatch, make_request(tmp_path), lines, exit_code=1)
    assert not result.success
    assert "código 1" in result.error
    assert session.removed == "/tmp/openmon-deploy.abc123"
    assert not (tmp_path / "etc" / "database.conf").exists()
    assert any(e.kind == "error" and "indisponível" in e.message for e in events)


def test_requires_fingerprint_and_credentials(tmp_path):
    req = make_request(tmp_path)
    req.ssh.password = None
    result = prov.DatabaseDeployer(req).run()
    assert not result.success and "senha ou a chave" in result.error


# -- TLS: mesmos comandos openssl do provision_db.sh, validados pelo check_tls --
def _make_pki(d: Path, sans: str):
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", "-new", "-nodes", "-sha256", "-days", "3650", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-keyout", d / "ca.key", "-out", d / "ca.crt",
        "-subj", "/O=OpenMon/CN=OpenMon Database CA test",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash")
    run("openssl", "req", "-new", "-nodes", "-sha256", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", d / "server.key", "-out", d / "server.csr", "-subj", "/O=OpenMon/CN=127.0.0.1")
    (d / "server.ext").write_text(
        "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyAgreement\n"
        f"extendedKeyUsage = serverAuth\nsubjectAltName = {sans}\nsubjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid, issuer\n")
    run("openssl", "x509", "-req", "-sha256", "-days", "825", "-in", d / "server.csr", "-CA", d / "ca.crt",
        "-CAkey", d / "ca.key", "-set_serial", "0x1234", "-extfile", d / "server.ext", "-out", d / "server.crt")


def _fake_postgres_tls(d: Path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "server.crt", d / "server.key")

    def serve():
        conn, _ = srv.accept()
        conn.recv(8)
        conn.sendall(b"S")
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_check_tls_verify_full_strict(tmp_path):
    _make_pki(tmp_path, "IP:127.0.0.1,DNS:localhost")
    port = _fake_postgres_tls(tmp_path)
    assert prov.check_tls("127.0.0.1", port, (tmp_path / "ca.crt").read_text()).startswith("TLS")


def test_check_tls_rejects_wrong_name(tmp_path):
    _make_pki(tmp_path, "IP:10.9.9.9")
    port = _fake_postgres_tls(tmp_path)
    with pytest.raises(ssl.SSLCertVerificationError):
        prov.check_tls("127.0.0.1", port, (tmp_path / "ca.crt").read_text())
