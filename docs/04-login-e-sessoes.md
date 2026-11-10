# 4. Primeiro administrador, login e sessões

Código em [`backend/openmon/api/setup.py`](../backend/openmon/api/setup.py) (etapa do
administrador), [`auth.py`](../backend/openmon/api/auth.py),
[`security.py`](../backend/openmon/api/security.py) e
[`db/pool.py`](../backend/openmon/db/pool.py). Telas em `frontend/public/`
(`index.html` assistente, `login.html`, `home.html`).

## Fluxo da instalação

| Estado | O que `https://IP_DA_VM1/` mostra |
|---|---|
| Sem banco, token ativo | Token → deploy do banco → administrador → login |
| Banco provisionado, sem `setup.done` | Token → administrador → login |
| `setup.done` gravado | Redireciona para `/login.html` (ou `/home.html` se já houver sessão) |

* O token de instalação vale até o administrador ser criado. Depois disso ele é
  apagado e `/var/lib/openmon/setup.done` é gravado.
* O instalador (`curl ... | sudo bash`) gera um token sempre que `setup.done` não
  existe. `--new-setup-token` apaga `setup.done` e reabre o assistente para
  refazer o deploy; se o banco já tiver usuários, a tela oferece "Encerrar o
  assistente e ir para o login" (`POST /api/setup/finish`).
* `POST /api/setup/admin` só cria o administrador se a tabela `users` estiver
  vazia (com `pg_advisory_xact_lock`, sem corrida entre dois navegadores). Papel
  `global_admin`, senha com 12+ caracteres que não contenha o nome de usuário,
  Argon2id (`m=64 MiB, t=3, p=4`). Fica registrado em `audit_log`
  (`setup.admin_create`) e em `auth.log`.

## Login

`POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`.

| Proteção | Como |
|---|---|
| Senha | Argon2id; usuário inexistente confere contra um hash fictício (mesmo tempo de resposta). Rehash automático se os parâmetros mudarem |
| Força bruta | 5 erros em 15 min bloqueiam a conta por 15 min (`system_settings` → `auth.lockout`). Vale também para nomes inexistentes, então a resposta não revela quem existe. Erros contam a partir do último login certo. Limite de 30 erros por IP na janela |
| Fail2ban | Cada tentativa vai para `login_attempts` e para `auth.log` (`auth.failure`, `auth.locked`, `auth.rate_limited`, `auth.success`); a jail bane o IP |
| Sessão | Token aleatório de 256 bits no cookie `__Host-openmon_session` (HttpOnly, Secure, SameSite=Strict, Path=/). No banco fica só o SHA-256 (`user_sessions`) |
| Expiração | 30 min sem uso e 12 h no máximo (`auth.session`). Logout revoga a sessão no banco |
| CSRF | `HMAC-SHA256(token_da_sessão)`, entregue no corpo de `/login` e `/me` e exigido em `X-CSRF-Token` nos métodos que alteram estado; o banco guarda o hash |
| Auditoria | `auth.login` e `auth.logout` em `audit_log` |

## Acesso ao banco pela API

`openmon/db/pool.py` lê `/etc/openmon/database/database.conf` (gravado pelo deploy)
e abre um pool asyncpg com TLS `verify-full` pela CA interna. Cada consulta roda em
`transaction(user_id, is_global, tenant_ids)`, que chama
`openmon.set_request_context` com escopo de transação: o RLS do PostgreSQL vê o
usuário da requisição e uma conexão devolvida ao pool não carrega contexto de
ninguém. Autenticação usa o contexto de sistema (`system_transaction()`).

## Testes

* `tests/test_auth.py`: cookie endurecido, CSRF, logout, mensagens genéricas,
  bloqueio (inclusive de nomes inexistentes), expiração por inatividade, Argon2id.
* `tests/test_api_setup.py`: etapa do administrador (token, política de senha,
  fechamento do assistente, caso "administrador já existe").
* Fluxo real no Chromium com a CSP de produção, contra o PostgreSQL 17 +
  TimescaleDB do container de e2e: deploy → administrador → login com senha
  errada → login → página inicial → logout; bloqueio após 5 erros conferido em
  `login_attempts`.

## Tela Segurança (Fail2ban, só na VM 1)

`/seguranca.html`, só para o Administrador Global (menu "Segurança"). Mostra:

* estado do Fail2ban e IPs bloqueados agora: automáticos (jail `openmon-auth`, por
  falhas de login no `auth.log`, 1 h com banimento progressivo) e manuais (jail
  `openmon-manual`, até desbloquear), com data, validade, motivo e autor;
* quem acessou nas últimas 24 h: requisições e erros do log do Apache
  (`openmon_access.log`) somados às tentativas de login (`login_attempts`), com
  usuários tentados e a última requisição; filtro por IP ou usuário;
* botões Bloquear/Desbloquear por linha, formulário com motivo e histórico.

O bloqueio vale só para 80/443 (o SSH continua acessível). O próprio IP do
administrador, loopback e endereços inválidos são recusados.

Como funciona sem dar privilégio à API:

| Peça | Usuário | Papel |
|---|---|---|
| API (`/api/admin/security/*`) | `openmon` | Lê `/var/lib/openmon/fail2ban/status.json` e grava pedidos em `/var/lib/openmon/fail2ban-requests/` (0600, `O_EXCL`), com CSRF, auditoria e `auth.log` |
| `openmon-fail2ban.path` | systemd | Dispara a ponte assim que chega um pedido |
| `openmon-fail2ban.timer` | systemd | Atualiza o estado e reaplica os bloqueios manuais a cada minuto |
| `/opt/openmon/bin/openmon-fail2ban` | root | Valida cada pedido (arquivo regular, ≤ 4 KB, sem symlink, ação em lista fechada, IP pelo `ipaddress`), chama o `fail2ban-client` sem shell e publica o estado (root:openmon 0640) |

A lista de bloqueios manuais fica em `/var/lib/openmon/fail2ban/manual.json` e é
reaplicada a cada minuto, então sobrevive a reinícios do Fail2ban. A VM 2 não tem
Fail2ban (não fica exposta).

Testado com Fail2ban 1.1 real (nftables): banimento automático a partir do
`auth.log`, bloqueio e desbloqueio pela tela, reaplicação após reinício e
pedidos maliciosos na fila (comando injetado, symlink, arquivo grande) ignorados.
