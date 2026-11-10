# 5. Tenants e usuários

Código em [`backend/openmon/api/admin_tenants.py`](../backend/openmon/api/admin_tenants.py)
e [`auth.py`](../backend/openmon/api/auth.py) (permissões e troca de senha). Telas
`tenants.html`, `usuarios.html` e `senha.html` em `frontend/public/`.

## Quem faz o quê

| Perfil | Escopo | Tenants | Usuários |
|---|---|---|---|
| Administrador global | todos os tenants | cria, edita, desativa, exclui | cria, edita, redefine senha, desbloqueia, exclui |
| Operador | todos os tenants | só lista | — |
| Cliente | só os tenants vinculados | — | — |

As permissões vêm de `role_permissions` (migration 0001): `tenants.manage` e
`users.manage` são do Administrador global. A sessão carrega a lista do banco a
cada requisição, então mudar o perfil de alguém vale na hora.

## Isolamento (duas barreiras)

1. **Backend:** cada rota exige a permissão e roda as consultas com o contexto
   da própria sessão (`session.db()` → `openmon.set_request_context`): perfil
   global vê tudo; Cliente só os tenants **ativos** a que está vinculado.
2. **Banco (RLS):** a API conecta como `openmon_app` (sem `BYPASSRLS`); as
   políticas da migration 0005 escondem as linhas dos outros tenants mesmo que
   a consulta esqueça um filtro. Os testes conferem isso num TimescaleDB real.

## Regras

* **Tenant do datacenter** (provedor): não pode ser desativado nem excluído.
* **Desativar um tenant** tira o acesso dos Clientes vinculados (um Cliente sem
  nenhum tenant ativo não entra: `no_active_tenant` em `login_attempts`). Os
  dados e o histórico ficam.
* **Excluir um tenant** só quando ele não tem usuários, ativos nem integrações;
  senão a API responde 409 e sugere desativar. A tela pede o identificador para
  confirmar.
* **Cliente** precisa de pelo menos um tenant; Administrador e Operador não têm
  vínculos (enxergam todos).
* Sempre sobra **um Administrador global ativo**; ninguém rebaixa, desativa ou
  exclui a própria conta.
* **Senha definida pelo administrador** (novo usuário ou "Senha") é provisória
  por padrão: o login leva para `senha.html` e a API recusa qualquer outra rota
  (`403 Troque a sua senha antes de continuar.`) até a troca. A tela sugere uma
  senha aleatória de 16 caracteres; a política é a mesma do administrador (12+
  caracteres, sem o nome de usuário).
* **Redefinir senha** e **desativar** encerram as sessões abertas do usuário.
  "Desbloquear" zera o bloqueio por tentativas erradas.
* **Trocar a própria senha** (`senha.html`, clique no seu nome no topo) pede a
  senha atual e encerra as suas outras sessões.

## Auditoria

Tudo vai para `audit_log` com quem fez, IP e o que mudou (nunca senhas):
`tenant.create`, `tenant.update`, `tenant.activate`, `tenant.deactivate`,
`tenant.delete`, `user.create`, `user.update`, `user.activate`,
`user.deactivate`, `user.password_reset`, `user.unlock`, `user.delete`,
`auth.password_change`. Criação, exclusão e redefinição de senha também saem no
`auth.log` (`admin.*`), que o Fail2ban ignora.

## API

| Método | Rota | Permissão |
|---|---|---|
| GET | `/api/admin/tenants` | perfis globais |
| POST | `/api/admin/tenants` | `tenants.manage` |
| PUT | `/api/admin/tenants/{id}` | `tenants.manage` |
| DELETE | `/api/admin/tenants/{id}` | `tenants.manage` |
| GET | `/api/admin/roles` | `users.manage` |
| GET | `/api/admin/users?tenant_id=` | `users.manage` |
| POST | `/api/admin/users` | `users.manage` |
| PUT | `/api/admin/users/{id}` | `users.manage` |
| POST | `/api/admin/users/{id}/password` | `users.manage` |
| POST | `/api/admin/users/{id}/unlock` | `users.manage` |
| DELETE | `/api/admin/users/{id}` | `users.manage` |
| POST | `/api/auth/password` | a própria sessão |

Métodos de escrita exigem `X-CSRF-Token`, como no resto da API.

## Testes com banco real

```bash
docker run -d --name omdb -e POSTGRES_PASSWORD=pgtest -p 55432:5432 timescale/timescaledb-ha:pg17
cd backend
OPENMON_TEST_PG=postgresql://postgres:pgtest@127.0.0.1:55432/postgres python3 -m pytest -q tests
```

Sem `OPENMON_TEST_PG` esses testes são pulados. O banco `openmon` desse
servidor é recriado com os papéis e as migrations do deploy.
