"""Deploy remoto do banco (VM 2) a partir do Frontend (VM 1), via SSH.

Fluxo (mesmo desenho do assistente do OpenFlow, endurecido):

  1. ``fetch_host_key`` -> o operador confirma a impressão digital SSH
  2. conexão autenticada com a chave fixada + ``preflight.sh`` (somente leitura)
  3. a VM 1 calcula o tuning, gera senhas, verificadores SCRAM e o pacote de SQL
  4. SFTP do pacote para ``/tmp/openmon-deploy.XXXX`` (0700) na VM 2
  5. ``provision_db.sh`` como root (sudo -S), com a saída transmitida ao vivo
  6. validação da conexão TLS (verify-full) a partir da VM 1
  7. gravação de ``/etc/openmon/database.conf`` (0640) e da CA em ``/etc/openmon/pki``

Uso síncrono: ``DatabaseDeployer(request, on_event).run()``.
Uso em FastAPI/asyncio: ``await deploy_async(request, on_event)``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shlex
import socket
import ssl
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from openmon.db import migrations
from openmon.deploy import scram, tuning
from openmon.deploy.ssh import SshError, SshSession, SshTarget

log = logging.getLogger("openmon.deploy")

REMOTE_DIR = Path(__file__).parent / "remote"
DB_NAME = "openmon"
# Chave de assinatura do apt.postgresql.org (https://www.postgresql.org/download/linux/debian/)
PGDG_KEY_FPR = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
SUPPORTED_PG_MAJORS = (15, 16, 17)
MIN_DEBIAN = 13

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_FPR_RE = re.compile(r"^[0-9A-F]{40}$")


class DeployError(RuntimeError):
    pass


# -----------------------------------------------------------------------------
# Modelos
# -----------------------------------------------------------------------------
@dataclass
class DeployRequest:
    ssh: SshTarget
    frontend_address: str                    # IP ou CIDR da VM 1 (liberado no pg_hba e no nftables)
    db_host: str | None = None               # endereço que a VM 1 usa para o banco (padrão: ssh.host)
    pg_major: int = 17
    db_port: int = 5432
    listen_addresses: str | None = None      # padrão: 'localhost,<db_host>' (ou '*' se db_host for DNS)
    manage_firewall: bool = True
    ssh_allow_cidrs: list[str] = field(default_factory=list)  # vazio = não restringe a porta 22
    timescale_key_fpr: str = ""
    max_connections: int = 150
    config_dir: Path = Path("/etc/openmon")
    write_config: bool = True
    validate_from_frontend: bool = True


@dataclass
class DeployEvent:
    kind: str          # step | log | info | warn | error | success
    message: str
    step: int = 0
    total: int = 0
    percent: int = 0
    key: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "message": self.message, "step": self.step,
                "total": self.total, "percent": self.percent, "key": self.key}


@dataclass
class DeployResult:
    success: bool
    host: str
    port: int
    database: str = DB_NAME
    app_user: str = migrations.APP_ROLE
    owner_user: str = migrations.OWNER_ROLE
    info: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    preflight: dict[str, str] = field(default_factory=dict)
    tuning: dict[str, str] = field(default_factory=dict)
    ca_cert_pem: str = ""
    config_path: str | None = None
    error: str | None = None
    app_password: str = field(default="", repr=False)
    owner_password: str = field(default="", repr=False)


EventCallback = Callable[[DeployEvent], None]


# -----------------------------------------------------------------------------
# Validação de entradas (tudo o que vai para shell, SQL ou arquivos de conf)
# -----------------------------------------------------------------------------
def normalize_cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise DeployError(f"endereço/CIDR inválido: {value!r}") from exc
    if net.prefixlen == 0:
        raise DeployError("liberar 0.0.0.0/0 ou ::/0 não é permitido")
    return str(net)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_host(value: str) -> str:
    value = value.strip()
    if is_ip(value) or _HOSTNAME_RE.match(value):
        return value
    raise DeployError(f"host inválido: {value!r}")


def parse_kv(output: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            if re.fullmatch(r"[A-Z_]+", key):
                data[key] = value.strip()
    return data


def check_preflight(pf: dict[str, str]) -> None:
    if pf.get("OS_ID") != "debian":
        raise DeployError(f"a VM 2 precisa ser Debian {MIN_DEBIAN}+ (detectado: {pf.get('OS_PRETTY', '?')})")
    version = pf.get("OS_VERSION_ID", "")
    if version:
        if int(version.split(".")[0]) < MIN_DEBIAN:
            raise DeployError(f"Debian {version} não suportado; use Debian {MIN_DEBIAN} (Trixie) ou superior")
    elif pf.get("OS_CODENAME") not in ("trixie", "forky"):
        raise DeployError(f"versão do Debian não identificada ({pf.get('OS_CODENAME') or '?'})")
    if pf.get("ARCH") not in ("amd64", "arm64"):
        raise DeployError(f"arquitetura {pf.get('ARCH')} não suportada pelo repositório TimescaleDB")
    if pf.get("SUDO") == "missing":
        raise DeployError("o usuário SSH não é root e o sudo não está instalado na VM 2")


def hardware_from_preflight(pf: dict[str, str]) -> tuning.Hardware:
    def as_int(key: str, default: int | None = None) -> int | None:
        try:
            return int(pf.get(key, ""))
        except ValueError:
            return default
    mem_kb = as_int("MEM_KB")
    mem = mem_kb * 1024 if mem_kb else None
    if not mem:
        raise DeployError("não foi possível detectar a memória da VM 2")
    return tuning.Hardware(
        mem_bytes=mem,
        cpus=as_int("CPUS", 1) or 1,
        rotational=pf.get("ROTATIONAL") == "1",
        disk_bytes=as_int("DISK_BYTES"),
    )


def certificate_sans(db_host: str, pf: dict[str, str]) -> tuple[str, str]:
    """(CN, subjectAltName) do certificado do servidor."""
    names: list[str] = []

    def add(entry: str) -> None:
        if entry not in names:
            names.append(entry)

    add(f"IP:{db_host}" if is_ip(db_host) else f"DNS:{db_host}")
    hostname = pf.get("HOSTNAME", "")
    if hostname and _HOSTNAME_RE.match(hostname):
        add(f"DNS:{hostname}")
    for ip in pf.get("IPS", "").split():
        if is_ip(ip) and not ipaddress.ip_address(ip).is_link_local:
            add(f"IP:{ip}")
    add("DNS:localhost")
    add("IP:127.0.0.1")
    return db_host, ",".join(names)


def render_params(values: dict[str, str]) -> str:
    lines = ["# OpenMon - parâmetros do deploy (gerado na VM 1, apagado ao final)"]
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z_]+", key):
            raise DeployError(f"parâmetro inválido: {key}")
        lines.append(f"{key}={shlex.quote(str(value))}")
    return "\n".join(lines) + "\n"


def render_roles_sql(owner_verifier: str, app_verifier: str) -> str:
    for verifier in (owner_verifier, app_verifier):
        if not re.fullmatch(r"SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+", verifier):
            raise DeployError("verificador SCRAM inválido")
    owner, app = migrations.OWNER_ROLE, migrations.APP_ROLE
    return f"""\\set ON_ERROR_STOP on
SELECT 'CREATE ROLE {owner}' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') \\gexec
SELECT 'CREATE ROLE {app}' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{app}') \\gexec
ALTER ROLE {owner} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    CONNECTION LIMIT 10 PASSWORD '{owner_verifier}';
ALTER ROLE {app} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD '{app_verifier}';
"""


# -----------------------------------------------------------------------------
# Validação a partir da VM 1
# -----------------------------------------------------------------------------
def check_tls(host: str, port: int, ca_pem: str, timeout: float = 10.0) -> str:
    """Faz o SSLRequest do protocolo PostgreSQL e valida o certificado (verify-full).

    Não depende de driver: confirma rota, firewall, TLS ativo e certificado
    emitido pela CA interna para o nome/IP usado pela VM 1. Devolve a versão TLS.
    """
    ctx = ssl.create_default_context(cadata=ca_pem)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!ii", 8, 80877103))
        answer = sock.recv(1)
        if answer != b"S":
            raise DeployError("o PostgreSQL recusou TLS (resposta ao SSLRequest diferente de 'S')")
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version() or "TLS"


def check_login(host: str, port: int, user: str, password: str, ca_file: str) -> str | None:
    """Login real com o papel da aplicação, se houver driver instalado (psycopg ou asyncpg)."""
    try:
        import psycopg  # type: ignore
    except ImportError:
        psycopg = None
    if psycopg is not None:
        with psycopg.connect(host=host, port=port, dbname=DB_NAME, user=user, password=password,
                             sslmode="verify-full", sslrootcert=ca_file, connect_timeout=10) as conn:
            row = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'").fetchone()
            return row[0] if row else None
    try:
        import asyncpg  # type: ignore
    except ImportError:
        return None

    async def _probe() -> str | None:
        ctx = ssl.create_default_context(cafile=ca_file)
        conn = await asyncpg.connect(host=host, port=port, database=DB_NAME, user=user,
                                     password=password, ssl=ctx, timeout=10)
        try:
            return await conn.fetchval("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
        finally:
            await conn.close()

    return asyncio.run(_probe())


# -----------------------------------------------------------------------------
# Arquivos na VM 1
# -----------------------------------------------------------------------------
def write_secure_file(path: Path, content: str, mode: int = 0o600, group: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        if group and os.geteuid() == 0:
            import grp
            try:
                os.fchown(fd, 0, grp.getgrnam(group).gr_gid)
            except KeyError:
                os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def render_database_conf(result: DeployResult, ca_file: str, *, owner: bool) -> str:
    user = result.owner_user if owner else result.app_user
    password = result.owner_password if owner else result.app_password
    purpose = "migrations (papel dono do schema)" if owner else "aplicação (API e coletores)"
    return (
        f"# OpenMon - conexão com o banco para {purpose}\n"
        "# Gerado pelo deploy do banco. Permissões restritas: contém senha.\n"
        "[database]\n"
        f"host = {result.host}\n"
        f"port = {result.port}\n"
        f"name = {result.database}\n"
        f"user = {user}\n"
        f"password = {password}\n"
        "sslmode = verify-full\n"
        f"sslrootcert = {ca_file}\n"
    )


# -----------------------------------------------------------------------------
# Orquestração
# -----------------------------------------------------------------------------
class DatabaseDeployer:
    def __init__(self, request: DeployRequest, on_event: EventCallback | None = None):
        self.req = request
        self._emit_cb = on_event or (lambda ev: None)
        self._secrets: list[str] = []
        self._step = 0
        self._total = 0

    # -- eventos -------------------------------------------------------------
    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            if secret:
                text = text.replace(secret, "********")
        return re.sub(r"SCRAM-SHA-256\$[^'\s]+", "SCRAM-SHA-256$********", text)

    def _emit(self, kind: str, message: str, percent: int | None = None, key: str | None = None) -> None:
        if percent is None:
            percent = self._remote_percent()
        event = DeployEvent(kind, self._redact(message), self._step, self._total, percent, key)
        log.log(logging.WARNING if kind in ("warn", "error") else logging.INFO, "%s", event.message)
        try:
            self._emit_cb(event)
        except Exception:  # um consumidor com defeito não pode derrubar o deploy
            log.exception("callback de evento falhou")

    def _remote_percent(self) -> int:
        if not self._total:
            return 10
        return 12 + int(83 * (self._step - 1) / self._total)

    # -- execução ------------------------------------------------------------
    def run(self) -> DeployResult:
        req = self.req
        db_host = validate_host(req.db_host or req.ssh.host)
        result = DeployResult(success=False, host=db_host, port=req.db_port)
        try:
            self._validate_request()
            self._secrets += [s for s in (req.ssh.password, req.ssh.sudo_password, req.ssh.key_passphrase) if s]
            self._emit("step", f"Conectando em {req.ssh.username}@{req.ssh.host}:{req.ssh.port} "
                               f"(chave {req.ssh.host_fingerprint})", 3)
            with SshSession(req.ssh) as session:
                self._emit("log", "Conexão SSH autenticada; chave do host confere.", 5)

                self._emit("step", "Verificando sistema operacional e hardware da VM 2", 6)
                code, out = session.run(f"bash -s <<'OPENMON_PREFLIGHT'\n{(REMOTE_DIR / 'preflight.sh').read_text()}\nOPENMON_PREFLIGHT")
                if code != 0:
                    raise DeployError(f"pré-verificação falhou: {out.strip()[-500:]}")
                pf = parse_kv(out)
                result.preflight = pf
                check_preflight(pf)
                if pf.get("SUDO") == "password" and not req.ssh.effective_sudo_password():
                    raise DeployError("o sudo da VM 2 exige senha; informe a senha do sudo")
                hw = hardware_from_preflight(pf)
                self._emit("log", f"{pf.get('OS_PRETTY')} ({pf.get('ARCH')}), {hw.cpus} vCPU, "
                                  f"{hw.mem_bytes // tuning.MB} MB RAM, disco "
                                  f"{'HDD' if hw.rotational else 'SSD/NVMe'}", 8)

                files, result = self._build_bundle(result, pf, hw)
                self._emit("step", "Enviando scripts e migrations via SFTP", 9)
                work_dir = session.make_work_dir()
                try:
                    session.upload_tree(files, work_dir)
                    self._emit("log", f"Pacote enviado para {work_dir} (permissão 0700).", 11)
                    exit_code = self._run_remote(session, work_dir, result)
                finally:
                    session.remove_work_dir(work_dir)
                if exit_code != 0:
                    raise DeployError(f"o provisionamento remoto terminou com código {exit_code}")
                if not result.ca_cert_pem:
                    raise DeployError("a VM 2 não devolveu o certificado da CA do banco")

            self._step = self._total
            if req.validate_from_frontend:
                self._validate_from_frontend(result)
            if req.write_config:
                self._save_config(result)
            result.success = True
            self._emit("success", f"Banco provisionado: PostgreSQL {result.info.get('server_version', '?')} + "
                                  f"TimescaleDB {result.info.get('timescaledb_version', '?')} em "
                                  f"{db_host}:{req.db_port} (TLS verify-full).", 100)
        except (DeployError, SshError, OSError, ssl.SSLError) as exc:
            result.error = self._redact(str(exc))
            self._emit("error", result.error)
        return result

    def _validate_request(self) -> None:
        req = self.req
        if req.pg_major not in SUPPORTED_PG_MAJORS:
            raise DeployError(f"PostgreSQL {req.pg_major} não suportado (use {SUPPORTED_PG_MAJORS})")
        if not 1 <= req.db_port <= 65535:
            raise DeployError("porta do PostgreSQL inválida")
        validate_host(req.ssh.host)
        normalize_cidr(req.frontend_address)
        for cidr in req.ssh_allow_cidrs:
            normalize_cidr(cidr)
        if req.timescale_key_fpr and not _FPR_RE.match(req.timescale_key_fpr):
            raise DeployError("impressão digital da chave TimescaleDB deve ter 40 hexadecimais maiúsculos")
        if req.listen_addresses is not None:
            for part in req.listen_addresses.split(","):
                part = part.strip()
                if part not in ("*", "localhost") and not is_ip(part) and not _HOSTNAME_RE.match(part):
                    raise DeployError(f"listen_addresses inválido: {part!r}")
        if not (req.ssh.password or req.ssh.private_key):
            raise DeployError("informe a senha ou a chave privada SSH")

    def _build_bundle(self, result: DeployResult, pf: dict[str, str], hw: tuning.Hardware):
        req = self.req
        db_host = result.host
        allow_cidr = normalize_cidr(req.frontend_address)
        ssh_cidrs = [normalize_cidr(c) for c in req.ssh_allow_cidrs]
        if ssh_cidrs and not any(ipaddress.ip_network(allow_cidr).subnet_of(ipaddress.ip_network(c))
                                 for c in ssh_cidrs if ipaddress.ip_network(c).version == ipaddress.ip_network(allow_cidr).version):
            ssh_cidrs.append(allow_cidr)  # nunca trancar a própria VM 1 fora do SSH
        listen = req.listen_addresses or (f"localhost,{db_host}" if is_ip(db_host) else "*")
        cn, sans = certificate_sans(db_host, pf)

        profile = tuning.TuningProfile(max_connections=req.max_connections)
        result.tuning = tuning.compute(hw, profile)

        result.app_password = scram.generate_password()
        result.owner_password = scram.generate_password()
        self._secrets += [result.app_password, result.owner_password]
        roles_sql = render_roles_sql(scram.scram_sha256_verifier(result.owner_password),
                                     scram.scram_sha256_verifier(result.app_password))

        params = render_params({
            "PG_MAJOR": str(req.pg_major),
            "DB_NAME": DB_NAME,
            "DB_PORT": str(req.db_port),
            "OWNER_ROLE": migrations.OWNER_ROLE,
            "APP_ROLE": migrations.APP_ROLE,
            "ALLOW_CIDR": allow_cidr,
            "LISTEN_ADDRESSES": listen,
            "CERT_CN": cn,
            "CERT_SANS": sans,
            "PGDG_KEY_FPR": PGDG_KEY_FPR,
            "TIMESCALE_KEY_FPR": req.timescale_key_fpr,
            "SSH_ALLOW_CIDRS": ",".join(ssh_cidrs),
            "MANAGE_FIREWALL": "1" if req.manage_firewall else "0",
        })

        files: dict[str, bytes] = {
            "provision_db.sh": (REMOTE_DIR / "provision_db.sh").read_bytes(),
            "params.env": params.encode(),
            "tuning.conf": tuning.render(hw, profile).encode(),
            "roles.sql": roles_sql.encode(),
            "sql/0000_bootstrap.sql": migrations.bootstrap_sql().encode(),
        }
        manifest = []
        for mig in migrations.discover():
            files[f"sql/{mig.version}.sql"] = mig.wrapped().encode()
            manifest.append(f"{mig.version} {mig.checksum}")
        files["sql/manifest"] = ("\n".join(manifest) + "\n").encode()
        return files, result

    def _run_remote(self, session: SshSession, work_dir: str, result: DeployResult) -> int:
        cert_lines: list[str] | None = None

        def on_line(line: str) -> None:
            nonlocal cert_lines
            if cert_lines is not None:
                if line == "::cert-end::":
                    result.ca_cert_pem = "\n".join(cert_lines) + "\n"
                    cert_lines = None
                else:
                    cert_lines.append(line)
                return
            if line == "::cert-begin::":
                cert_lines = []
            elif line.startswith("::step::"):
                _, _, n, total, text = line.split("::", 4)
                self._step, self._total = int(n), int(total)
                self._emit("step", f"[{n}/{total}] {text}")
            elif line.startswith("::info::"):
                _, _, key, value = line.split("::", 3)
                result.info[key] = value
                self._emit("info", f"{key}: {value}", key=key)
            elif line.startswith("::warn::"):
                result.warnings.append(self._redact(line[8:]))
                self._emit("warn", line[8:])
            elif line.startswith("::error::"):
                self._emit("error", line[9:])
            elif line == "::done::":
                self._emit("log", "Provisionamento remoto concluído.", 95)
            elif line.strip():
                self._emit("log", line)

        command = f"bash {shlex.quote(work_dir + '/provision_db.sh')} {shlex.quote(work_dir)}"
        return session.run_streaming(command, on_line, as_root=True)

    def _validate_from_frontend(self, result: DeployResult) -> None:
        self._emit("step", "Validando a conexão TLS a partir do Frontend (VM 1)", 96)
        try:
            version = check_tls(result.host, result.port, result.ca_cert_pem)
        except (OSError, ssl.SSLError) as exc:
            raise DeployError(
                f"a VM 1 não conseguiu abrir TLS com {result.host}:{result.port}: {exc}. "
                "Verifique rota, firewall e se o IP liberado é o IP de saída desta VM.") from exc
        self._emit("log", f"TLS {version} com certificado validado (verify-full).", 97)
        with tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False) as fh:
            fh.write(result.ca_cert_pem)
            ca_tmp = fh.name
        try:
            ts = check_login(result.host, result.port, result.app_user, result.app_password, ca_tmp)
        except Exception as exc:  # driver presente mas login falhou
            raise DeployError(f"login com {result.app_user} falhou: {exc}") from exc
        finally:
            os.unlink(ca_tmp)
        if ts is None:
            self._emit("warn", "Nenhum driver PostgreSQL (psycopg/asyncpg) instalado na VM 1; "
                               "login validado apenas na VM 2.", 98)
        else:
            self._emit("log", f"Login como {result.app_user} OK; TimescaleDB {ts} ativo.", 98)

    def _save_config(self, result: DeployResult) -> None:
        cfg = self.req.config_dir
        ca_file = cfg / "pki" / "db-ca.crt"
        write_secure_file(ca_file, result.ca_cert_pem, mode=0o644)
        write_secure_file(cfg / "database.conf", render_database_conf(result, str(ca_file), owner=False),
                          mode=0o640, group="openmon")
        write_secure_file(cfg / "database-owner.conf", render_database_conf(result, str(ca_file), owner=True),
                          mode=0o600)
        ssh = self.req.ssh
        host_entry = ssh.host if ssh.port == 22 else f"[{ssh.host}]:{ssh.port}"
        write_secure_file(cfg / "ssh" / "db_host_fingerprint", f"{host_entry} {ssh.host_fingerprint}\n", mode=0o644)
        result.config_path = str(cfg / "database.conf")
        self._emit("log", f"Configuração gravada em {result.config_path}.", 99)


async def deploy_async(
    request: DeployRequest,
    on_event: Callable[[DeployEvent], Awaitable[None] | None] | None = None,
) -> DeployResult:
    """Executa o deploy numa thread e entrega os eventos no event loop (FastAPI/WebSocket)."""
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[DeployEvent | None] = asyncio.Queue()

    def bridge(event: DeployEvent) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    future = loop.run_in_executor(None, DatabaseDeployer(request, bridge).run)
    future.add_done_callback(lambda _f: loop.call_soon_threadsafe(queue.put_nowait, None))
    while (event := await queue.get()) is not None:
        if on_event is not None:
            maybe = on_event(event)
            if asyncio.iscoroutine(maybe):
                await maybe
    return await future
