# OpenMon

Plataforma web open source, enxuta e multi-tenant para monitoramento de
infraestrutura de datacenter: VMware vSphere, Microsoft Hyper-V, backups Veeam,
redes e links via SNMP. Inspirada na arquitetura do Zabbix e construída sobre os
padrões do projeto OpenFlow.

* **2 VMs Debian 13 (Trixie) ou superior**: VM 1 com Apache2 + API + coletores
  (`systemd`), VM 2 com PostgreSQL + TimescaleDB.
* **Séries temporais com 5 anos de histórico**: hypertables, continuous aggregates
  horárias e diárias, compressão nativa.
* **Multi-tenancy estrito**: cada cliente vê só os próprios ativos, métricas, links,
  backups e relatórios; isolamento também no banco (Row-Level Security).
* **Security by design**: cofre AES-256-GCM, Argon2id, TLS entre as VMs, CSP/HSTS,
  `systemd` com sandbox, `nftables`, Fail2ban.

## Instalação em um comando

Duas VMs com **Debian 13 limpo**. Na VM 2 (banco) basta ter SSH com um usuário
que tenha `sudo` (ou acesso root por chave). Tudo é feito a partir da VM 1:

```bash
curl -fsSL https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
  | sudo bash -s -- --db-host IP_DA_VM2 --db-ssh-user USUARIO
```

O instalador prepara a VM 1 (pacotes apt, `/opt/openmon`, `/etc/openmon` com a
chave mestra, Apache2 com HTTPS e headers de segurança, units `systemd`,
Fail2ban) e em seguida faz o deploy do PostgreSQL + TimescaleDB na VM 2 via SSH:
mostra a impressão digital SSH da VM 2 para você confirmar, pede a senha e
transmite as 9 etapas ao vivo. Sem `--db-host`, ele pergunta o IP da VM 2 no fim
(Enter pula; dá para rodar de novo depois).

<details>
<summary>Repositório privado</summary>

Enquanto o repositório for privado, o GitHub responde 404 sem token. Gere um
token de leitura (fine-grained, só `Contents: Read` neste repositório) e passe-o
pelo cabeçalho e pelo ambiente, nunca dentro da URL:

```bash
TOKEN=github_pat_...
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
  | sudo GITHUB_TOKEN="$TOKEN" bash -s -- --db-host IP_DA_VM2 --db-ssh-user USUARIO
```
</details>

Outras opções: `--db-ssh-key /root/.ssh/id_ed25519`, `--ssh-allow 10.10.0.0/24`
(restringe o SSH da VM 2), `--admin-cidr 10.10.0.0/24` (ativa o nftables da VM 1),
`--fqdn openmon.empresa.local`, `--skip-db`. Para atualizar, rode o mesmo comando.

> O Debian não aceita login SSH do `root` por senha por padrão
> (`PermitRootLogin prohibit-password`). Use um usuário com `sudo` ou uma chave.

## Estado atual

| Etapa | Status |
|---|---|
| 1. Estrutura de diretórios (FHS), pacotes apt, units systemd, Apache2, nftables, Fail2ban | ✅ [docs/01-arquitetura-debian.md](docs/01-arquitetura-debian.md) |
| 2. Schema PostgreSQL + TimescaleDB (tenancy, cofre, ativos, hypertables, caggs, retenção) | ✅ [docs/02-banco-de-dados.md](docs/02-banco-de-dados.md) |
| 3. Deploy remoto do banco via SSH | ✅ [docs/03-deploy-banco-ssh.md](docs/03-deploy-banco-ssh.md) |
| 4. API (auth local + AD, RBAC, CSRF, cofre) e assistente web do deploy | próximo |
| 5. Coletores vCenter, Hyper-V, Veeam e SNMP | — |
| 6. Dashboards, relatórios (PDF/CSV, 60 meses), alertas, backup/restauração | — |

## Estrutura do repositório

```
backend/
  openmon/db/migrations/   SQL do schema (0001..0005)
  openmon/db/migrations.py descoberta, checksum e empacotamento das migrations
  openmon/deploy/          deploy do banco via SSH (paramiko), tuning, SCRAM, CLI
  openmon/deploy/remote/   scripts bash executados na VM 2
  tests/                   testes unitários (pytest) e e2e/ (deploy real via SSH em container)
packaging/
  apt/                     listas de pacotes das duas VMs
  apache2/                 VirtualHost e headers de segurança
  systemd/                 openmon-*.service, .timer, .path, openmon.target
  nftables/ fail2ban/ logrotate/ tmpfiles.d/
scripts/install.sh         instalador one-liner da VM 1 (curl | sudo bash)
bin/                       utilitários administrativos instalados em /opt/openmon/bin
docs/                      arquitetura, banco e deploy
```

## Testes

```bash
cd backend
python3 -m pytest -q tests                        # unitários
docker build -t openmon-e2e-vm2 tests/e2e && python3 tests/e2e/run_e2e.py   # ponta a ponta
```

## Licença

A definir pelo mantenedor. Observação: o TimescaleDB Community (compressão e
continuous aggregates) é distribuído sob a Timescale License; veja
[docs/01-arquitetura-debian.md](docs/01-arquitetura-debian.md#pacotes-apt).
