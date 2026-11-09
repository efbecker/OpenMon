"""Sessão SSH do deployer (paramiko) com fixação da chave do host.

Diferenças em relação ao deployer do OpenFlow, de propósito:

* Nada de ``AutoAddPolicy``: a chave do host é obtida *antes* de qualquer
  autenticação (:func:`fetch_host_key`), mostrada ao operador e só então
  aceita. Conexões seguintes exigem a mesma impressão digital, evitando que
  um MITM capture a senha do SSH.
* A senha do ``sudo`` é escrita no stdin do canal (``sudo -S``), nunca na
  linha de comando (onde ficaria visível em ``ps`` na VM 2).
* Autenticação por chave privada (Ed25519/ECDSA/RSA) é suportada e preferida.
"""
from __future__ import annotations

import base64
import hashlib
import io
import shlex
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import paramiko


class SshError(RuntimeError):
    pass


class HostKeyMismatch(SshError):
    pass


@dataclass(frozen=True)
class HostKey:
    key_type: str
    fingerprint: str  # formato OpenSSH: SHA256:base64-sem-padding
    public_b64: str

    @classmethod
    def from_pkey(cls, key: paramiko.PKey) -> "HostKey":
        return cls(key.get_name(), fingerprint_of(key), key.get_base64())


def fingerprint_of(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fetch_host_key(host: str, port: int = 22, timeout: float = 10.0) -> HostKey:
    """Lê a chave pública do servidor SSH sem autenticar (nenhum segredo é enviado)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise SshError(f"não foi possível conectar em {host}:{port}: {exc}") from exc
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return HostKey.from_pkey(transport.get_remote_server_key())
    except paramiko.SSHException as exc:
        raise SshError(f"falha na negociação SSH com {host}:{port}: {exc}") from exc
    finally:
        transport.close()


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected_fingerprint: str):
        self.expected = expected_fingerprint.strip()

    def missing_host_key(self, client, hostname, key):  # noqa: D401 - API do paramiko
        got = fingerprint_of(key)
        if got != self.expected:
            raise HostKeyMismatch(
                f"a chave SSH de {hostname} mudou: esperado {self.expected}, recebido {got}. "
                "Possível ataque man-in-the-middle ou servidor reinstalado; confirme antes de continuar."
            )


def load_private_key(pem: str, passphrase: str | None = None) -> paramiko.PKey:
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=passphrase)
        except (paramiko.SSHException, ValueError) as exc:
            errors.append(f"{cls.__name__}: {exc}")
    raise SshError("chave privada SSH inválida ou passphrase incorreta")


@dataclass
class SshTarget:
    host: str
    port: int = 22
    username: str = "root"
    password: str | None = None
    private_key: str | None = None
    key_passphrase: str | None = None
    host_fingerprint: str = ""  # obrigatório: confirmado pelo operador
    sudo_password: str | None = None  # padrão: a senha do SSH, se houver

    def effective_sudo_password(self) -> str | None:
        return self.sudo_password if self.sudo_password is not None else self.password


class SshSession:
    """Conexão SSH autenticada com a VM 2."""

    def __init__(self, target: SshTarget, timeout: float = 20.0):
        if not target.host_fingerprint:
            raise SshError("a impressão digital da chave do host não foi confirmada")
        self.target = target
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(_PinnedHostKeyPolicy(target.host_fingerprint))
        pkey = load_private_key(target.private_key, target.key_passphrase) if target.private_key else None
        try:
            self.client.connect(
                hostname=target.host,
                port=target.port,
                username=target.username,
                password=target.password,
                pkey=pkey,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except HostKeyMismatch:
            self.client.close()
            raise
        except (paramiko.SSHException, OSError) as exc:
            self.client.close()
            raise SshError(f"falha ao autenticar em {target.username}@{target.host}:{target.port}: {exc}") from exc

    # -- context manager -----------------------------------------------------
    def __enter__(self) -> "SshSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.client.close()

    # -- comandos ------------------------------------------------------------
    def run(self, command: str, timeout: float = 60.0) -> tuple[int, str]:
        """Comando curto sem privilégios; devolve (código, stdout+stderr)."""
        lines: list[str] = []
        code = self.run_streaming(command, lines.append, timeout=timeout)
        return code, "\n".join(lines)

    def run_streaming(
        self,
        command: str,
        on_line: Callable[[str], None],
        *,
        as_root: bool = False,
        timeout: float = 3600.0,
    ) -> int:
        """Executa e entrega a saída linha a linha. Com ``as_root`` usa sudo quando necessário."""
        sudo_password = None
        if as_root and self.target.username != "root":
            sudo_password = self.target.effective_sudo_password()
            if sudo_password:
                # -k ignora credenciais em cache: a senha enviada é sempre consumida pelo sudo
                command = f"sudo -S -k -p '' -- {command}"
            else:
                command = f"sudo -n -- {command}"
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise SshError("conexão SSH encerrada")
        channel = transport.open_session(timeout=30)
        channel.settimeout(timeout)
        channel.set_combine_stderr(True)
        channel.exec_command(command)
        if sudo_password:
            channel.sendall((sudo_password + "\n").encode("utf-8"))
        channel.shutdown_write()

        buffer = b""
        try:
            while True:
                chunk = channel.recv(32768)
                if not chunk:
                    break
                buffer += chunk
                *lines, buffer = buffer.split(b"\n")
                for line in lines:
                    on_line(line.decode("utf-8", errors="replace").rstrip("\r"))
        except socket.timeout as exc:
            channel.close()
            raise SshError(f"tempo limite excedido executando o provisionamento ({int(timeout)} s)") from exc
        if buffer:
            on_line(buffer.decode("utf-8", errors="replace").rstrip("\r"))
        return channel.recv_exit_status()

    def make_work_dir(self) -> str:
        code, out = self.run("umask 077 && mktemp -d /tmp/openmon-deploy.XXXXXXXXXX")
        path = out.strip().splitlines()[-1] if out.strip() else ""
        if code != 0 or not path.startswith("/tmp/openmon-deploy."):
            raise SshError(f"não foi possível criar diretório temporário na VM 2: {out.strip()}")
        return path

    def upload_tree(self, files: dict[str, bytes], remote_dir: str) -> None:
        """Envia ``{caminho_relativo: conteúdo}`` via SFTP com permissões 0600/0700."""
        sftp = self.client.open_sftp()
        try:
            made: set[str] = set()
            for rel, content in sorted(files.items()):
                parts = Path(rel).parts
                if any(p in ("..", "") for p in parts) or Path(rel).is_absolute():
                    raise SshError(f"caminho inválido para upload: {rel}")
                current = remote_dir
                for part in parts[:-1]:
                    current = f"{current}/{part}"
                    if current not in made:
                        try:
                            sftp.mkdir(current, mode=0o700)
                        except OSError:
                            if not stat.S_ISDIR(sftp.stat(current).st_mode):
                                raise
                        made.add(current)
                remote_path = f"{remote_dir}/{rel}"
                with sftp.open(remote_path, "wb") as fh:
                    fh.chmod(0o600)
                    fh.write(content)
        finally:
            sftp.close()

    def remove_work_dir(self, remote_dir: str) -> None:
        if remote_dir.startswith("/tmp/openmon-deploy."):
            self.run(f"rm -rf -- {shlex.quote(remote_dir)}", timeout=30)
