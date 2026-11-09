# 2. Schema do banco (PostgreSQL 17 + TimescaleDB)

Migrations em [`backend/openmon/db/migrations/`](../backend/openmon/db/migrations/),
aplicadas em ordem, cada uma numa transação, como o papel `openmon_owner`.
Controle em `openmon.schema_migrations` (versão + SHA-256 do arquivo).

| Arquivo | Conteúdo |
|---|---|
| `0001_core_tenancy_auth_vault.sql` | Tenants, RBAC (perfis/permissões), LDAP/AD, usuários, sessões, tentativas de login, cofre de credenciais, auditoria, configurações |
| `0002_assets_integrations.sql` | Integrações (vCenter, Hyper-V, Veeam, SNMP), ativos, regras de atribuição a tenants, SNMP, interfaces, estado dos contadores 64-bit, catálogo de métricas |
| `0003_timeseries.sql` | Hypertables de métricas e de tráfego, continuous aggregates hierárquicos, compressão e retenção |
| `0004_backups_alerts_system.sql` | Jobs/sessões Veeam, canais de notificação, triggers, problemas, entregas, backup/restauração do OpenMon |
| `0005_security_rls_grants.sql` | Funções de contexto, Row-Level Security, views seguras, `interface_p95()`, GRANTs |

## Papéis

| Papel | Uso | Privilégios |
|---|---|---|
| `postgres` | Só no deploy (local, via `runuser`) | Cria a extensão `timescaledb` |
| `openmon_owner` | Migrations | Dono do schema `openmon`; dono dos jobs do TimescaleDB |
| `openmon_app` | API e coletores | DML nas tabelas relacionais (com RLS), só `INSERT` nas hypertables e na auditoria, leitura das séries só pelas views `v_*`. Sem DDL, sem `BYPASSRLS` |

Os dois papéis de login só entram por `hostssl` a partir do IP da VM 1, com `scram-sha-256`.

## Multi-tenancy estrito

* Todo dado de cliente carrega `tenant_id`. A infraestrutura compartilhada (core,
  vCenters, Veeam) pertence ao tenant provedor (`tenants.is_provider`).
* Perfis `scope = 'global'` (Admin Global, Operador) veem todos os tenants;
  `scope = 'tenant'` (Cliente) vê só os tenants em `user_tenants`. Grupos do AD
  são mapeados para perfil + tenant em `ldap_group_mappings`.
* Defesa em duas camadas contra IDOR:
  1. o backend valida o `tenant_id` de cada recurso contra a sessão;
  2. o banco aplica o mesmo filtro. No início de cada transação a API chama
     `SELECT openmon.set_request_context(user_id, is_global, tenant_ids)`; o valor
     dura só a transação. **Sem contexto, nenhuma linha de cliente aparece**.
* Tabelas relacionais usam RLS (`tenant_isolation`); tabelas de sistema
  (LDAP, sessões, cofre de chaves, backup) aceitam só o contexto global.
* O TimescaleDB não permite RLS em tabelas comprimidas, então as hypertables e as
  continuous aggregates não são legíveis pela aplicação: a leitura passa pelas
  views `v_metric_*`, `v_interface_*` e `v_audit_log` (`security_barrier`), com o
  mesmo filtro.
* Se um ativo muda de cliente, o histórico anterior continua com o cliente antigo
  (o `tenant_id` é gravado em cada amostra).

## Cofre de credenciais (`credentials`)

* AES-256-GCM feito na VM 1; o banco guarda `nonce` (12 bytes) e `ciphertext`
  (com a tag de 16 bytes). A chave mestra fica em `/etc/openmon/master.key` (0400).
* AAD: `openmon:cred:v1:<id>:<kind>`, que impede trocar o ciphertext de uma
  credencial para outra linha.
* `key_version` + `vault_keys.key_check` (HMAC da chave) permitem rotação da
  chave mestra e detectam arquivo de chave errado sem expô-la.
* Tipos: SSH (senha/chave), VMware, WinRM, Veeam, bind do AD, SNMP v2c/v3, SMTP,
  bot do Telegram, webhook. Parâmetros não secretos (ex.: protocolo de
  autenticação SNMPv3) ficam em `params` (jsonb).

## Senhas e auditoria

* `users.password_hash` aceita apenas strings PHC Argon2id ou Bcrypt (CHECK).
* `login_attempts` (hypertable, 180 dias) alimenta o rate limiting; o mesmo evento
  vai para `/var/log/openmon/auth.log` para o Fail2ban.
* `audit_log` (hypertable, comprimida, 62 meses) é append-only para a aplicação.
* Nenhum usuário padrão é criado pelas migrations: o instalador cria o primeiro
  admin com senha aleatória.

## Séries temporais e retenção de 5 anos

```
metric_samples (bruto, ~60 s) ──► metric_hourly ──► metric_daily
interface_samples (bruto) ──► interface_5m ──► interface_hourly ──► interface_daily
```

| Objeto | Granularidade | Comprime após | Retenção |
|---|---|---|---|
| `metric_samples` | bruto | 2 dias | 35 dias |
| `metric_hourly` | 1 h | 7 dias | 25 meses |
| `metric_daily` | 1 dia | 45 dias | 62 meses |
| `interface_samples` | bruto | 2 dias | 35 dias |
| `interface_5m` | 5 min (base do p95) | 7 dias | 13 meses |
| `interface_hourly` | 1 h | 14 dias | 25 meses |
| `interface_daily` | 1 dia | 45 dias | 62 meses |
| `audit_log` | evento | 60 dias | 62 meses |

* As agregações são hierárquicas (diária a partir da horária), com
  `materialized_only = false` (mostram também o período ainda não materializado).
* Médias são reagregadas por soma/contagem; a média é calculada nas views.
  `metric_daily.peak_hour_avg` guarda a maior média horária do dia (capacity planning).
* O relatório de crescimento de 60 meses lê `v_metric_daily` / `v_interface_daily`.
* Percentil 95 de banda: `openmon.interface_p95(interface_id, de, até)` sobre
  amostras de 5 min (exato para períodos de até 13 meses). Para períodos maiores
  o relatório usa o pico diário de 5 min.
* A retenção é ajustável em `system_settings` (`retention.*`) e aplicada por
  `openmon.apply_retention_settings()`, que só roda no contexto global e recusa
  valores abaixo do mínimo seguro de cada camada.
* Buckets em UTC; o fuso de exibição é aplicado na consulta.
* O backup do Veeam fica em tabelas relacionais (volume baixo), com upsert do
  status das sessões em andamento.

## Como foi testado

Contra PostgreSQL 17.11 + TimescaleDB 2.31.0, via o próprio deploy (ver
`backend/tests/e2e/run_e2e.py`): as 5 migrations aplicam sem erro, 4 hypertables
e 5 continuous aggregates com 22 jobs; inserção de dados sintéticos, refresh das
caggs, médias diárias corretas, p95 correto, isolamento por tenant nas views e
no p95, recusa de leitura direta da hypertable e de UPDATE na auditoria, e
compressão de chunk com leitura posterior.
