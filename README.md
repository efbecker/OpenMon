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
