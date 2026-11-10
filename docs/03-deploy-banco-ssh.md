# 3. Deploy remoto do banco via SSH (VM 1 → VM 2)

Código em [`backend/openmon/deploy/`](../backend/openmon/deploy/). Segue o desenho
do `db_deployer.py` do OpenFlow (paramiko, SFTP de um script bash, saída
transmitida ao vivo em etapas, gravação da configuração no fim), com as mudanças
de segurança listadas abaixo.

## Fluxo

| # | Onde | O que acontece |
|---|---|---|
| 0 | VM 1 | `fetch_host_key()` lê a chave SSH da VM 2 **sem autenticar**; o operador confirma a impressão digital |
| 1 | VM 1 → 2 | Conexão autenticada (senha ou chave Ed25519/ECDSA/RSA); a chave do host precisa bater com a confirmada |
| 2 | VM 2 | `preflight.sh` (somente leitura): Debian ≥ 13, arquitetura, CPUs, RAM, disco SSD/HDD, sudo |
| 3 | VM 1 | Calcula o tuning, gera as senhas dos papéis e os **verificadores SCRAM**, monta o pacote de SQL |
| 4 | VM 1 → 2 | SFTP para `/tmp/openmon-deploy.XXXXXXXXXX` (0700, arquivos 0600) |
| 5 | VM 2 | `provision_db.sh` como root (`sudo -S`), 9 etapas, saída ao vivo |
| 6 | VM 1 | Valida TLS com `verify-full` e faz login com `openmon_app` |
| 7 | VM 1 | Grava `/etc/openmon/database.conf`, `database-owner.conf` e `pki/db-ca.crt` |

Etapas do `provision_db.sh` (idempotente; pode rodar de novo):

1. Valida Debian 13+ (`/etc/os-release`), amd64/arm64
2. `apt-get` não interativo (`DEBIAN_FRONTEND=noninteractive`, `--force-confold`): pacotes base
3. Repositórios oficiais em deb822 com `Signed-By`: PGDG (`trixie-pgdg`, chave conferida pela impressão digital `B97B0AFC…ACCC4CF8`) e TimescaleDB (`packagecloud.io/timescale`)
4. `postgresql-17`, `timescaledb-2-postgresql-17`, `timescaledb-tools`; falha se a `.so` do TimescaleDB não existir
5. CA interna + certificado do servidor (EC P-256, SAN com IP/DNS da VM 2); reemitido se os nomes mudarem ou faltarem 30 dias para vencer
6. `conf.d/00-openmon.conf` (TLS, scram, `shared_preload_libraries`, logs), `conf.d/10-openmon-tuning.conf`, bloco gerenciado no `pg_hba.conf`; reinicia e **restaura a configuração anterior** se o PostgreSQL não subir ou se o `pg_hba` tiver erro
7. Papéis, banco `openmon` (UTF-8, `C.UTF-8`), extensão TimescaleDB e migrations pendentes
8. nftables: tabela `inet openmon_db` (5432 só da VM 1), persistida em `/etc/nftables.d/` e ativada no boot
9. Validação: versões, `ssl = on`, hypertables, caggs, jobs, versão do schema

## Segurança: o que muda em relação ao OpenFlow

| OpenFlow | OpenMon |
|---|---|
| `AutoAddPolicy` (aceita qualquer chave SSH) | Chave do host obtida antes da autenticação, confirmada e fixada; divergência aborta antes de enviar a senha |
| Senha do sudo em `echo 'senha' \| sudo -S` na linha de comando | Senha escrita no stdin do canal; nunca aparece em `ps` |
| Senha do banco em texto no script remoto | Só o verificador SCRAM vai para a VM 2; a senha fica na VM 1 |
| `/tmp/openflow_schema.sql` com modo 0666 | Diretório `mktemp` 0700, arquivos 0600, apagado no fim (também em falha) |
| `host all all 127.0.0.1/32 trust` e regra `md5` | Só `hostssl` + `scram-sha-256` da VM 1; `hostnossl` rejeitado |
| Fallback silencioso sem TimescaleDB | TimescaleDB é obrigatório; sem ele o deploy falha com mensagem clara |
| Conexão sem TLS | TLS obrigatório com CA própria e `sslmode=verify-full` |
| Regras nft avulsas, sem persistência | Tabela própria, validada com `nft -c`, persistida e idempotente |
| Banco renomeado/dados legados | Não se aplica (projeto novo) |

Todas as entradas que viram shell, SQL ou arquivo de configuração (IPs, CIDRs,
hosts, `listen_addresses`) são validadas e passadas por `shlex.quote` ou por
variáveis do `psql` (`:'var'`). Senhas são removidas de qualquer mensagem de log.

## Tuning automático

`openmon/deploy/tuning.py`, a partir do hardware lido via SSH:

| Parâmetro | Regra |
|---|---|
| `shared_buffers` | 25 % da RAM (128 MB–32 GB) |
| `effective_cache_size` | 75 % da RAM |
| `maintenance_work_mem` | 5 % da RAM (64 MB–2 GB) |
| `work_mem` | (RAM − shared_buffers) / (conexões × 3) / workers por gather (4–256 MB) |
| paralelismo | `max_parallel_workers` = CPUs; por gather e manutenção = CPUs/2 (1–4) |
| `timescaledb.max_background_workers` | 16 (as 22 políticas do schema rodam em paralelo) |
| `max_worker_processes` | workers TimescaleDB + CPUs + 3 |
| WAL | `max_wal_size` = 5 % do disco (2–16 GB), `wal_compression = lz4` |
| disco | SSD: `random_page_cost = 1.1`, `effective_io_concurrency = 256`; HDD: 4.0 / 2 |

Ajustes manuais vão em `conf.d/99-local.conf`, que o deploy não sobrescreve.

## Uso

Pelo instalador, numa VM 1 recém-instalada (faz a VM 1 e já dispara este deploy):

```bash
curl -fsSL https://raw.githubusercontent.com/efbecker/OpenMon/main/scripts/install.sh \
  | sudo bash -s -- --db-host 10.10.0.20 --db-ssh-user admin
```

O instalador descobre sozinho o IP de saída da VM 1 até a VM 2 (`ip route get`)
e o usa em `--frontend-address`. As perguntas (impressão digital, senhas) vão
pelo terminal (`/dev/tty`), então funcionam mesmo com `curl | bash`.

Pela CLI (o assistente web vai usar o mesmo motor):

```bash
sudo PYTHONPATH=/opt/openmon/app python3 -m openmon.deploy \
    --db-host 10.10.0.20 --ssh-user admin --ssh-key /root/.ssh/id_ed25519 \
    --frontend-address 10.10.0.10 --ssh-allow 10.10.0.0/24
```

Pelo código (FastAPI + WebSocket, como o `DatabaseDeployWizard` do OpenFlow):

```python
from openmon.deploy import DeployRequest, SshTarget, deploy_async, fetch_host_key

key = fetch_host_key("10.10.0.20")          # mostrar key.fingerprint ao operador
req = DeployRequest(ssh=SshTarget(host="10.10.0.20", username="admin", password=pw,
                                  host_fingerprint=key.fingerprint),
                    frontend_address="10.10.0.10")
result = await deploy_async(req, on_event=lambda ev: websocket.send_json(ev.as_dict()))
```

Cada evento traz `kind` (`step`, `log`, `info`, `warn`, `error`, `success`),
`message`, `step`/`total` e `percent` para a barra de progresso.

## Testes

* `pytest backend/tests`: 28 testes unitários (SCRAM conferido com um verificador
  gerado pelo próprio PostgreSQL 17, tuning, validação de entradas, citação no
  shell, fluxo completo com SSH simulado, TLS `verify-full` com os mesmos comandos
  `openssl` do script, inclusive o modo estrito do Python 3.13).
* `backend/tests/e2e/run_e2e.py`: deploy real via SSH (senha + `sudo -S`) contra um
  container com sshd, PostgreSQL 17.11 e TimescaleDB 2.31: dois deploys seguidos
  (idempotência), login TLS `verify-full` a partir do host, RLS, caggs, p95,
  recusa de conexão sem TLS, regra nftables e recusa de chave SSH trocada.
  Limitação: o ambiente de teste não alcança os espelhos do Debian, então o
  container usa a imagem `timescaledb-ha` (Ubuntu + pacotes PGDG/Timescale) com
  `os-release` de Debian 13 e `apt-get` simulado. As etapas 2–4 (instalação via apt
  e repositórios) **ainda precisam ser homologadas numa VM Debian 13 real**.
