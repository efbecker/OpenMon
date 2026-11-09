"""CLI do deploy do banco (mesmo motor usado pelo assistente web).

Exemplo, na VM 1 como root:

    python3 -m openmon.deploy --db-host 10.10.0.20 --ssh-user admin \\
        --frontend-address 10.10.0.10 --ssh-key /root/.ssh/id_ed25519
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from openmon.deploy.provisioner import DatabaseDeployer, DeployEvent, DeployRequest
from openmon.deploy.ssh import SshError, SshTarget, fetch_host_key


def _print_event(event: DeployEvent) -> None:
    prefix = {"step": "==>", "info": "  -", "warn": "[AVISO]", "error": "[ERRO]", "success": "[OK]"}.get(event.kind, "   ")
    print(f"{event.percent:3d}% {prefix} {event.message}", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="openmon-deploy-db", description="Provisiona PostgreSQL + TimescaleDB na VM 2 via SSH")
    p.add_argument("--db-host", required=True, help="IP/DNS da VM 2 (SSH e PostgreSQL)")
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--ssh-user", default="root")
    p.add_argument("--ssh-key", type=Path, help="chave privada SSH (preferível a senha)")
    p.add_argument("--frontend-address", required=True, help="IP/CIDR da VM 1 liberado no pg_hba e no nftables")
    p.add_argument("--fingerprint", help="impressão digital SSH esperada (SHA256:...); sem ela, pergunta")
    p.add_argument("--pg-major", type=int, default=17)
    p.add_argument("--db-port", type=int, default=5432)
    p.add_argument("--ssh-allow", action="append", default=[], help="CIDR com acesso SSH à VM 2 (repetível)")
    p.add_argument("--no-firewall", action="store_true", help="não gerenciar nftables na VM 2")
    p.add_argument("--timescale-key-fpr", default="", help="impressão digital esperada da chave apt do TimescaleDB")
    p.add_argument("--config-dir", type=Path, default=Path("/etc/openmon"))
    args = p.parse_args(argv)

    try:
        host_key = fetch_host_key(args.db_host, args.ssh_port)
    except SshError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 2
    print(f"Chave SSH de {args.db_host}: {host_key.key_type} {host_key.fingerprint}")
    if args.fingerprint:
        if args.fingerprint != host_key.fingerprint:
            print("[ERRO] a impressão digital não confere com --fingerprint", file=sys.stderr)
            return 2
    elif input("Confere com a chave da VM 2 (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub)? [s/N] ").strip().lower() not in ("s", "sim", "y", "yes"):
        return 1

    private_key = args.ssh_key.read_text() if args.ssh_key else None
    passphrase = password = sudo_password = None
    if private_key and "ENCRYPTED" in private_key:
        passphrase = getpass.getpass("Passphrase da chave SSH: ")
    if not private_key:
        password = getpass.getpass(f"Senha SSH de {args.ssh_user}@{args.db_host}: ")
    elif args.ssh_user != "root":
        sudo_password = getpass.getpass("Senha do sudo (Enter se NOPASSWD): ") or None

    request = DeployRequest(
        ssh=SshTarget(host=args.db_host, port=args.ssh_port, username=args.ssh_user, password=password,
                      private_key=private_key, key_passphrase=passphrase,
                      host_fingerprint=host_key.fingerprint, sudo_password=sudo_password),
        frontend_address=args.frontend_address,
        pg_major=args.pg_major,
        db_port=args.db_port,
        manage_firewall=not args.no_firewall,
        ssh_allow_cidrs=args.ssh_allow,
        timescale_key_fpr=args.timescale_key_fpr,
        config_dir=args.config_dir,
    )
    result = DatabaseDeployer(request, _print_event).run()
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
