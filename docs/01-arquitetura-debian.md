# 1. Arquitetura, estrutura de diretórios (FHS) e pacotes — Debian 13+

## Visão geral

```
                     HTTPS 443 (TLS 1.2/1.3, HSTS, CSP)
  Navegador ───────────────────────────────┐
                                           ▼
 ┌──────────────────────── VM 1 · Debian 13+ ───────────────────────────┐
 │ Apache2  ── /var/www/openmon/public (SPA, só estáticos)              │
 │    │ mod_proxy → unix:/run/openmon/api.sock (sem porta TCP exposta)  │
 │    ▼                                                                 │
 │ openmon-api.service        FastAPI/uvicorn (auth, RBAC, tenants)     │
 │ openmon-scheduler.service  triggers, notificações, relatórios        │
 │ openmon-collector@vmware   vCenter (PropertyCollector/PerfManager)   │
 │ openmon-collector@hyperv   WinRM/CIM, 1 sessão PowerShell por host   │
 │ openmon-collector@veeam    Veeam REST API                            │
 │ openmon-collector@snmp     SNMP v2c/v3 (base do OpenFlow)            │
 │ openmon-backup.timer       pg_dump + configs → /var/backups/openmon  │
 │ nftables · fail2ban (auth.log) · /etc/openmon/master.key (0400)      │
 └──────────────┬───────────────────────────────────────────────────────┘
                │ PostgreSQL 5432 com TLS verify-full (scram-sha-256)
                │ SSH 22 só para o deploy/manutenção
 ┌──────────────▼──────── VM 2 · Debian 13+ ────────────────────────────┐
 │ PostgreSQL 17 (PGDG) + TimescaleDB 2.x (repo oficial Timescale)      │
 │ hypertables + continuous aggregates + compressão + retenção 5 anos   │
 │ pg_hba: hostssl apenas da VM 1 · nftables: 5432 só para a VM 1       │
 └──────────────────────────────────────────────────────────────────────┘
```

Todo o código da aplicação é Python 3.13 (versão do Debian 13), o mesmo stack
do OpenFlow (FastAPI + paramiko + asyncpg), para reaproveitar os módulos
de SNMP, LDAP, deploy e relatórios. O OpenFlow usa Nginx; aqui o Apache2 assume
o papel de proxy reverso e servidor dos estáticos, no padrão Debian
(`sites-available`, `a2enmod`, `a2ensite`).

## Estrutura de diretórios na VM 1

| Caminho | Dono / modo | Conteúdo |
|---|---|---|
| `/opt/openmon/` | `root:root 0755` | Código da aplicação, somente leitura para o serviço |
| `/opt/openmon/app/openmon/` | `root:root 0755` | Pacote Python (`api`, `collector`, `scheduler`, `db/migrations`, `deploy`) |
| `/opt/openmon/bin/` | `root:root 0755` | Utilitários administrativos (ex.: `openmon-backup-reschedule`) |
| `/opt/openmon/venv/` | `root:root 0755` | Opcional: venv `--system-site-packages` só para libs que não existam no Debian |
| `/var/www/openmon/public/` | `root:root 0755` | `DocumentRoot` do Apache: build do frontend. Nenhum segredo ou código de servidor |
| `/etc/openmon/` | `root:openmon 0750` | Configuração |
| `/etc/openmon/openmon.conf` | `root:openmon 0640` | Configuração geral da aplicação |
| `/etc/openmon/master.key` | `openmon:openmon 0400` | Chave mestra AES-256-GCM do cofre (32 bytes aleatórios) |
| `/etc/openmon/database.conf` | `root:openmon 0640` | Conexão do papel `openmon_app` (gerado pelo deploy do banco) |
| `/etc/openmon/database-owner.conf` | `root:root 0600` | Conexão do papel dono do schema, só para migrations |
| `/etc/openmon/pki/db-ca.crt` | `0644` | CA interna do PostgreSQL (TLS verify-full) |
| `/etc/openmon/ssh/` | `0750` | Impressão digital SSH fixada da VM 2 |
| `/var/lib/openmon/` | `openmon:openmon 0750` | Estado: `spool/` (filas), `reports/` (PDF/CSV gerados), pedido de agendamento do backup |
| `/var/log/openmon/` | `openmon:adm 0750` | `app.log`, `collector.log`, `auth.log` (JSON por linha, lido pelo Fail2ban) |
| `/var/backups/openmon/` | `openmon:openmon 0700` | Pacotes `openmon_<data>_<tipo>.tar.zst` |
| `/run/openmon/` | `openmon:www-data 2750` | `api.sock` (o Apache acessa pelo grupo) |
| `/etc/systemd/system/openmon-*.service`, `.timer`, `.path`, `openmon.target` | `root 0644` | Serviços |
| `/etc/apache2/sites-available/openmon.conf` | `root 0644` | VirtualHost 80→443 e proxy da API |
| `/etc/apache2/conf-available/openmon-security.conf` | `root 0644` | Headers de segurança, TLS, CSP |
| `/etc/fail2ban/filter.d/openmon-auth.conf`, `jail.d/openmon.conf` | `root 0644` | Banimento por força bruta |
| `/etc/nftables.d/openmon-frontend.nft` | `root 0644` | Firewall da VM 1 |
| `/etc/logrotate.d/openmon`, `/etc/tmpfiles.d/openmon.conf` | `root 0644` | Rotação de logs e diretórios |

Usuário de serviço: `openmon` (sistema, sem shell, sem home útil):
`adduser --system --group --home /var/lib/openmon --no-create-home --shell /usr/sbin/nologin openmon`.

A chave mestra fica fora do `DocumentRoot`, legível só pelo usuário `openmon`,
e os serviços rodam com `ProtectSystem=strict`, ou seja, `/etc/openmon` é
somente leitura até para a própria aplicação.

## Estrutura na VM 2

| Caminho | Conteúdo |
|---|---|
| `/etc/postgresql/17/main/conf.d/00-openmon.conf` | Base: `listen_addresses`, TLS, scram, `shared_preload_libraries = 'timescaledb'`, logs |
| `/etc/postgresql/17/main/conf.d/10-openmon-tuning.conf` | Tuning calculado pelo hardware detectado via SSH |
| `/etc/postgresql/17/main/conf.d/99-local.conf` | Livre para ajustes manuais (o deploy não toca) |
| `/etc/postgresql/17/main/pg_hba.conf` | Bloco `# BEGIN OPENMON ... # END OPENMON` no topo |
| `/etc/postgresql/17/main/tls/` | `ca.crt`/`ca.key` (root 0600), `server.crt`/`server.key` (postgres 0600) |
| `/var/lib/postgresql/17/main/` | Dados (padrão Debian) |
| `/etc/apt/keyrings/{pgdg.asc,timescaledb.gpg}` | Chaves dos repositórios (conferidas por impressão digital) |
| `/etc/apt/sources.list.d/{pgdg,timescaledb}.sources` | Repositórios no formato deb822 |
| `/etc/nftables.d/openmon-db.nft` | Tabela `inet openmon_db`: 5432 só para a VM 1 |

## Pacotes apt

Listas prontas para `xargs apt-get install`: [`packaging/apt/vm1-frontend.txt`](../packaging/apt/vm1-frontend.txt)
e [`packaging/apt/vm2-database.txt`](../packaging/apt/vm2-database.txt).

### VM 1 — somente repositório oficial do Debian (main)

| Grupo | Pacotes | Para quê |
|---|---|---|
| Sistema | `ca-certificates curl openssl sudo chrony nftables fail2ban logrotate zstd unattended-upgrades python3-systemd` | Base, hora certa (TLS e séries temporais), firewall, anti brute force, compressão dos backups |
| Web | `apache2` | mod_ssl, mod_headers, mod_proxy, mod_proxy_http, mod_proxy_wstunnel e mod_http2 já vêm no pacote |
| Python | `python3 python3-venv` | Python 3.13 |
| API | `python3-fastapi python3-uvicorn python3-pydantic python3-multipart python3-jinja2` | API, uploads (restore), templates de relatório/e-mail |
| Banco | `python3-asyncpg python3-psycopg postgresql-client-17` | Driver assíncrono, driver síncrono para migrations, `pg_dump`/`pg_restore` na mesma versão do servidor |
| Segurança | `python3-cryptography python3-argon2 python3-bcrypt python3-jwt python3-ldap3` | AES-256-GCM, Argon2id/Bcrypt, tokens, LDAPS/StartTLS |
| Coletores | `python3-httpx python3-paramiko python3-winrm python3-requests-ntlm python3-pyvmomi snmp` | REST (vCenter/Veeam), SSH (deploy), WinRM/PowerShell (Hyper-V), SOAP PerfManager, `snmpwalk` para diagnóstico |

Opcionais: `python3-certbot-apache` (Let's Encrypt), `krb5-user` + `python3-requests-kerberos`
(WinRM com Kerberos em vez de NTLM).

> Não consegui consultar o arquivo do Debian a partir deste ambiente. Antes de
> fechar o instalador, confirme com `apt-cache policy` na VM 1 os pacotes
> `python3-pyvmomi` e `python3-requests-ntlm`. Se algum faltar no Trixie, ele vai
> para o venv `--system-site-packages` em `/opt/openmon/venv` e os demais seguem do apt.

### VM 2 — Debian + repositórios oficiais PGDG e Timescale

| Origem | Pacotes |
|---|---|
| Debian main | `ca-certificates curl gnupg openssl nftables chrony postgresql-common unattended-upgrades` |
| apt.postgresql.org (`trixie-pgdg`) | `postgresql-17 postgresql-client-17` |
| packagecloud.io/timescale (`trixie`) | `timescaledb-2-postgresql-17 timescaledb-tools` |

O deploy via SSH instala tudo isso sozinho (ver [03-deploy-banco-ssh.md](03-deploy-banco-ssh.md)).

> **Licença do TimescaleDB:** compressão, continuous aggregates e políticas
> automáticas fazem parte da edição *Community* (Timescale License, TSL), que
> vem do repositório oficial da Timescale. É gratuita para uso próprio, inclusive
> comercial, mas não é OSI open source. A edição Apache-2 pura não tem esses
> recursos, e sem eles a retenção de 5 anos com baixo consumo de disco não
> funciona. O OpenMon em si continua open source.

## Serviços systemd

Arquivos em [`packaging/systemd/`](../packaging/systemd/):

| Unit | Função |
|---|---|
| `openmon.target` | Agrupa tudo: `systemctl start openmon.target` |
| `openmon-api.service` | uvicorn em socket Unix, 4 workers |
| `openmon-collector@.service` | Instâncias `vmware`, `hyperv`, `veeam`, `snmp`; cada uma é um pool asyncio de workers com fila |
| `openmon-scheduler.service` | Triggers, notificações, relatórios agendados, limpeza de sessões |
| `openmon-backup.service` + `.timer` | Backup agendado (padrão 02:30) |
| `openmon-backup-reschedule.path` + `.service` | A API grava o horário escolhido no painel; o root valida com `systemd-analyze calendar` e aplica o drop-in. A API nunca escreve em `/etc` |

Isolamento aplicado em todos: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RestrictNamespaces`,
`SystemCallFilter=@system-service`, `CapabilityBoundingSet=` (vazio),
`MemoryDenyWriteExecute`, `ReadWritePaths` só onde precisa. Confira com
`systemd-analyze security openmon-api.service`.

## Apache2

```bash
a2enmod ssl headers proxy proxy_http proxy_wstunnel rewrite http2
cp packaging/apache2/openmon-security.conf /etc/apache2/conf-available/
cp packaging/apache2/openmon.conf /etc/apache2/sites-available/
a2enconf openmon-security && a2dissite 000-default && a2ensite openmon
apachectl configtest && systemctl reload apache2
```

Headers: HSTS (2 anos), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
CSP sem `unsafe-inline`/`unsafe-eval`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP.
`ServerTokens Prod`, `TraceEnable Off`, TLS 1.2/1.3.

## Firewall (nftables) entre as VMs

* VM 1 (`packaging/nftables/vm1-frontend.nft`): entrada só 80/443 e SSH das redes de
  administração; saída para a VM 2 só nas portas 22 e 5432.
* VM 2 (gerado pelo deploy): tabela própria `inet openmon_db` que aceita 5432 só da
  VM 1 e descarta o resto. Opcionalmente restringe SSH (`--ssh-allow`), sempre
  mantendo a VM 1 liberada. O deploy não apaga regras existentes de outras tabelas.

## Dimensionamento sugerido (5.000 VMs)

| | VM 1 | VM 2 |
|---|---|---|
| vCPU | 8 | 8 |
| RAM | 16 GB | 32 GB |
| Disco | 60 GB | 500 GB SSD/NVMe (dados) |

Estimativa do banco com 5.000 VMs × ~20 métricas a cada 60 s (100 mil séries):
~144 M linhas/dia brutas; com a compressão nativa (tipicamente 10–20×) ficam
~25 GB para os 35 dias brutos, ~15 GB para 25 meses de agregados horários e
~2 GB para 5 anos de diários. São estimativas; o painel de banco vai mostrar o
consumo real por camada.
