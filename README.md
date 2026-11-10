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
  `systemd` com sandbox, Fail2ban. Sem firewall local: o OpenMon fica atrás do
  firewall do ambiente e o banco só aceita a VM 1 no `pg_hba.conf`.

## Instalação em um comando

Duas VMs com **Debian 13 limpo**. Na VM 1 (Frontend):

```bash
curl -fsSL https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh | sudo bash
```

O instalador prepara a VM 1 (pacotes apt, `/opt/openmon`, `/etc/openmon` com a
chave mestra, Apache2 com HTTPS e headers de segurança, units `systemd`,
Fail2ban, API) e mostra no final o endereço e um **token de instalação**.

Depois, o banco da VM 2 é instalado **pela interface web**: abra
`https://IP_DA_VM1/`, cole o token e preencha IP, porta e usuário SSH (com sudo)
da VM 2, a senha e o IP da VM 1. "Testar Conexão SSH" mostra a impressão digital
da chave da VM 2 para você conferir e testa o login; "Fazer Deploy" instala
PostgreSQL + TimescaleDB com o terminal ao vivo. Na VM 2 basta Debian 13 com SSH.

Assim que o deploy termina, a mesma tela pede o **administrador global**
(usuário + senha de 12+ caracteres, guardada como Argon2id). Ao criar, o
assistente é encerrado, o token deixa de valer e o navegador vai para a
**tela de login** (`https://IP_DA_VM1/login.html`); `https://IP_DA_VM1/`
passa a levar sempre ao login ou à página inicial. Para refazer o deploy do
banco depois disso, rode o instalador com `--new-setup-token`.

> Instalou antes desta versão (banco provisionado, sem administrador)? Rode o
> mesmo comando curl de novo: ele gera um novo token e o assistente abre direto
> na criação do administrador.

<details>
<summary>Repositório privado</summary>

Enquanto o repositório for privado, o GitHub responde 404 sem token. Gere um
token de leitura (fine-grained, só `Contents: Read` neste repositório) e passe-o
pelo cabeçalho e pelo ambiente, nunca dentro da URL:

```bash
TOKEN=github_pat_...
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
  | sudo GITHUB_TOKEN="$TOKEN" bash
```
</details>

Outras opções: `--fqdn openmon.empresa.local`, `--new-setup-token`. Para
atualizar, rode o mesmo comando.

> O Debian não aceita login SSH do `root` por senha por padrão
> (`PermitRootLogin prohibit-password`). Use um usuário com `sudo`.

## Estado atual

| Etapa | Status |
|---|---|
| 1. Estrutura de diretórios (FHS), pacotes apt, units systemd, Apache2, Fail2ban | ✅ [docs/01-arquitetura-debian.md](docs/01-arquitetura-debian.md) |
| 2. Schema PostgreSQL + TimescaleDB (tenancy, cofre, ativos, hypertables, caggs, retenção) | ✅ [docs/02-banco-de-dados.md](docs/02-banco-de-dados.md) |
| 3. Deploy remoto do banco via SSH | ✅ [docs/03-deploy-banco-ssh.md](docs/03-deploy-banco-ssh.md) |
| 4. Assistente web do deploy do banco (token de instalação, terminal ao vivo) | ✅ |
| 5a. Primeiro administrador, login local (Argon2id, sessão, CSRF, bloqueio), página inicial | ✅ [docs/04-login-e-sessoes.md](docs/04-login-e-sessoes.md) |
| 5b. Tela Segurança: acessos, IPs bloqueados, bloquear/desbloquear (Fail2ban) | ✅ [docs/04-login-e-sessoes.md](docs/04-login-e-sessoes.md#tela-segurança-fail2ban-só-na-vm-1) |
| 5c. Tenants e usuários por tenant (RBAC, RLS, senha provisória, auditoria) | ✅ [docs/05-tenants-e-usuarios.md](docs/05-tenants-e-usuarios.md) |
| 5d. Login AD/LDAP opcional (LDAPS/StartTLS, grupos → perfil + tenant, cofre AES-256-GCM) | ✅ [docs/06-active-directory.md](docs/06-active-directory.md) |
| 6. Coletores vCenter, Hyper-V, Veeam e SNMP | — |
| 7. Dashboards, relatórios (PDF/CSV, 60 meses), alertas, backup/restauração | — |

## Estrutura do repositório

```
backend/
  openmon/db/migrations/   SQL do schema (0001..0005)
  openmon/db/migrations.py descoberta, checksum e empacotamento das migrations
  openmon/deploy/          deploy do banco via SSH (paramiko), tuning, SCRAM, CLI
  openmon/deploy/remote/   scripts bash executados na VM 2
  openmon/api/             API FastAPI (assistente de instalação em /api/setup)
frontend/public/           interface web estática (HTML/CSS/JS, compatível com CSP estrita)
  tests/                   testes unitários (pytest) e e2e/ (deploy real via SSH em container)
packaging/
  apt/                     listas de pacotes das duas VMs
  apache2/                 VirtualHost e headers de segurança
  systemd/                 openmon-*.service, .timer, .path, openmon.target
  fail2ban/ logrotate/ tmpfiles.d/
scripts/install.sh         instalador one-liner da VM 1 (curl | sudo bash)
bin/                       utilitários administrativos instalados em /opt/openmon/bin
docs/                      arquitetura, banco e deploy
```

## Testes

```bash
cd backend
python3 -m pytest -q tests                        # unitários
OPENMON_TEST_PG=postgresql://postgres:SENHA@127.0.0.1:55432/postgres python3 -m pytest -q tests  # + RLS num TimescaleDB real
docker build -t openmon-e2e-vm2 tests/e2e && python3 tests/e2e/run_e2e.py   # ponta a ponta
```

## Licença

A definir pelo mantenedor. Observação: o TimescaleDB Community (compressão e
continuous aggregates) é distribuído sob a Timescale License; veja
[docs/01-arquitetura-debian.md](docs/01-arquitetura-debian.md#pacotes-apt).
