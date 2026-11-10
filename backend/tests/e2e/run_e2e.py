"""Teste ponta a ponta do deploy do banco via SSH contra o container openmon-e2e-vm2.

    docker build -t openmon-e2e-vm2 backend/tests/e2e
    python3 backend/tests/e2e/run_e2e.py

Executa o deploy duas vezes (idempotência), valida TLS verify-full, login do
papel da aplicação, isolamento por tenant (RLS) e a recusa de chave SSH trocada.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from openmon.deploy import DatabaseDeployer, DeployRequest, SshTarget, fetch_host_key  # noqa: E402
from openmon.deploy.ssh import HostKeyMismatch, SshSession  # noqa: E402

NAME = "openmon-e2e-vm2"


def sh(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def start() -> tuple[str, str]:
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    sh("docker", "run", "-d", "--name", NAME, "--cap-add", "NET_ADMIN", NAME)
    info = json.loads(sh("docker", "inspect", NAME))[0]["NetworkSettings"]
    net = next(iter(info["Networks"].values()))
    ip, gateway = net["IPAddress"], net["Gateway"]
    for _ in range(30):
        try:
            fetch_host_key(ip, 22, timeout=2)
            break
        except Exception:
            time.sleep(1)
    return ip, gateway


def deploy(ip: str, gateway: str, fingerprint: str, config_dir: Path):
    events = []

    def show(ev):
        events.append(ev)
        if ev.kind != "log":
            print(f"{ev.percent:3d}% [{ev.kind}] {ev.message}")

    req = DeployRequest(
        ssh=SshTarget(host=ip, username="admin", password="Adm1n-E2E-pass", host_fingerprint=fingerprint),
        frontend_address=gateway,
        config_dir=config_dir,
    )
    return DatabaseDeployer(req, show).run(), events


def main() -> int:
    ip, gateway = start()
    hk = fetch_host_key(ip)
    print(f"VM 2 simulada em {ip}; Frontend (host) = {gateway}; chave {hk.fingerprint}")
    cfg = Path(tempfile.mkdtemp(prefix="openmon-e2e-cfg."))

    result, events = deploy(ip, gateway, hk.fingerprint, cfg)
    assert result.success, result.error
    assert result.info["ssl"] == "on"
    assert int(result.info["hypertables"]) == 4 and int(result.info["continuous_aggregates"]) == 5
    assert result.info["migrations_applied"] == "5"
    print("-- 1º deploy OK:", {k: result.info[k] for k in ("server_version", "timescaledb_version", "shared_buffers", "background_jobs")})

    # Login e RLS como openmon_app, a partir do "Frontend"
    import psycopg
    conf = dict(line.split(" = ", 1) for line in (cfg / "database.conf").read_text().splitlines() if " = " in line)
    with psycopg.connect(host=conf["host"], port=int(conf["port"]), dbname=conf["name"], user=conf["user"],
                         password=conf["password"], sslmode="verify-full", sslrootcert=conf["sslrootcert"]) as conn:
        assert conn.info.pgconn.ssl_in_use
        assert conn.execute("SELECT count(*) FROM openmon.tenants").fetchone()[0] == 0, "sem contexto deveria ver 0"
        with conn.transaction():
            conn.execute("SELECT openmon.set_request_context(NULL, true, NULL)")
            assert conn.execute("SELECT count(*) FROM openmon.tenants").fetchone()[0] == 1
        try:
            conn.execute("SELECT count(*) FROM openmon.metric_samples")
            raise AssertionError("app não deveria ler a hypertable diretamente")
        except psycopg.errors.InsufficientPrivilege:
            conn.rollback()
    print("-- login TLS verify-full + RLS OK")

    # Dados sintéticos como dono do schema, caggs atualizadas, leitura isolada por tenant como app
    owner = dict(line.split(" = ", 1) for line in (cfg / "database-owner.conf").read_text().splitlines() if " = " in line)
    with psycopg.connect(host=owner["host"], port=int(owner["port"]), dbname=owner["name"], user=owner["user"],
                         password=owner["password"], sslmode="verify-full", sslrootcert=owner["sslrootcert"],
                         autocommit=True) as oc:
        oc.execute("INSERT INTO openmon.tenants (slug, name) VALUES ('cliente-a', 'A'), ('cliente-b', 'B')")
        oc.execute("""INSERT INTO openmon.metric_samples
                      SELECT t, 2 + (g % 2), g, 1, 50 FROM generate_series(now() - interval '2 days', now(), interval '1 minute') t,
                             generate_series(1, 4) g""")
        oc.execute("""INSERT INTO openmon.interface_samples
                      SELECT t, 2, 1, 10, 60, 750000000, 75000000, 0, 0, 100000000, 10000000, 0, 0, 0, 0, 1
                      FROM generate_series(now() - interval '1 day', now(), interval '1 minute') t""")
        for cagg in ("metric_hourly", "metric_daily", "interface_5m", "interface_hourly", "interface_daily"):
            oc.execute(f"CALL refresh_continuous_aggregate('openmon.{cagg}', NULL, NULL)")
    with psycopg.connect(host=conf["host"], port=int(conf["port"]), dbname=conf["name"], user=conf["user"],
                         password=conf["password"], sslmode="verify-full", sslrootcert=conf["sslrootcert"]) as conn:
        with conn.transaction():
            conn.execute("SELECT openmon.set_request_context(NULL, false, ARRAY[2]::bigint[])")
            tenants = {r[0] for r in conn.execute("SELECT DISTINCT tenant_id FROM openmon.v_metric_hourly")}
            assert tenants == {2}, tenants
            avg = conn.execute("SELECT round(avg(avg_value)) FROM openmon.v_metric_daily").fetchone()[0]
            assert avg == 50, avg
            p95 = conn.execute("SELECT in_p95_bps FROM openmon.interface_p95(10, now() - interval '2 days', now())").fetchone()[0]
            assert round(p95) == 100_000_000, p95
        with conn.transaction():
            conn.execute("SELECT openmon.set_request_context(NULL, false, ARRAY[3]::bigint[])")
            assert conn.execute("SELECT samples FROM openmon.interface_p95(10, now() - interval '2 days', now())").fetchone()[0] == 0
    print("-- continuous aggregates + p95 + isolamento nas views OK")

    # Conexão sem TLS deve ser recusada pelo pg_hba
    try:
        psycopg.connect(host=conf["host"], port=int(conf["port"]), dbname=conf["name"], user=conf["user"],
                        password=conf["password"], sslmode="disable", connect_timeout=5).close()
        raise AssertionError("conexão sem TLS foi aceita")
    except psycopg.OperationalError as exc:
        assert "reject" in str(exc) or "no pg_hba.conf entry" in str(exc) or "rejects" in str(exc), exc
    print("-- conexão sem TLS recusada OK")

    # Idempotência: segundo deploy não reaplica migrations e mantém o certificado
    ca_before = result.ca_cert_pem
    result2, _ = deploy(ip, gateway, hk.fingerprint, cfg)
    assert result2.success, result2.error
    assert result2.info["migrations_applied"] == "0"
    assert result2.ca_cert_pem == ca_before
    print("-- 2º deploy idempotente OK")

    # Sem firewall gerenciado pelo OpenMon (o acesso é restrito pelo pg_hba)
    tables = sh("docker", "exec", NAME, "nft", "list", "tables")
    assert "openmon_db" not in tables, tables
    print("-- nenhuma regra nftables criada OK")

    # Chave do host trocada -> recusa antes de autenticar
    try:
        SshSession(SshTarget(host=ip, username="admin", password="x",
                             host_fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        raise AssertionError("chave trocada foi aceita")
    except HostKeyMismatch:
        print("-- chave SSH divergente recusada OK")

    # Nenhum resto do pacote de deploy na VM 2
    assert sh("docker", "exec", NAME, "sh", "-c", "ls -d /tmp/openmon-deploy.* 2>/dev/null || true") == ""
    print("E2E: todos os cenários passaram")
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
