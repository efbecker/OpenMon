# 6. Active Directory / LDAP (opcional)

Código em [`backend/openmon/ldapauth.py`](../backend/openmon/ldapauth.py) (conexão,
busca, grupos), [`api/admin_ldap.py`](../backend/openmon/api/admin_ldap.py)
(configuração), [`api/auth.py`](../backend/openmon/api/auth.py) (login) e
[`vault.py`](../backend/openmon/vault.py) (cofre). Tela `ad.html` (menu **AD/LDAP**,
só Administrador global).

## Como configurar

1. No AD, crie uma conta de serviço só com leitura (ex.: `svc-openmon`) e os
   grupos de acesso, por exemplo `OpenMon-Admins`, `OpenMon-NOC` e um grupo por
   cliente (`OpenMon-Cliente-ACME`).
2. Em **AD/LDAP → Novo diretório**: controladores de domínio pelo nome DNS
   (`dc1.empresa.local, dc2.empresa.local`, sem `ldap://`), Segurança (StartTLS na
   389 ou LDAPS na 636) e Porta, Base DN, conta de serviço (*Bind DN*: DN completo ou
   `svc-openmon@empresa.local`) e senha. Se o certificado do DC vem da CA interna,
   cole a CA (PEM) em *Avançado* ou desmarque **Verificar o certificado do
   controlador de domínio**. Em "Grupos do AD com acesso" vão **grupos**, não a
   conta de serviço.
3. Em **Testar**, informe um usuário (e, se quiser, a senha dele): a tela mostra
   cada etapa (TLS, conta de serviço, usuário, grupos, senha) e os grupos do
   usuário, com um botão **Mapear** em cada um.
4. Mapeie os grupos: perfil Administrador global, Operador ou Cliente (+ tenant).
   O resultado do teste mostra o acesso que o usuário teria. Salve.

## Regras do login

* **Conta local tem precedência:** se existe usuário local com o nome digitado,
  o AD nem é consultado. Os demais nomes vão para o AD.
* **Perfil pelos grupos:** vale o perfil mais alto entre os grupos mapeados do
  usuário (Administrador global > Operador > Cliente). Para Cliente, os tenants
  de todos os grupos de Cliente se somam (tenants desativados não contam).
  Quem não está em nenhum grupo mapeado recebe "sem grupo com acesso".
* **Provisionamento no primeiro login:** a conta aparece em **Usuários** com a
  marca *AD*. A cada login o nome, o e-mail, o perfil e os tenants são
  atualizados pelos grupos. Desativar a conta em Usuários bloqueia o acesso
  mesmo com a senha do AD certa.
* **Grupos aninhados** do AD são considerados (`LDAP_MATCHING_RULE_IN_CHAIN`).
  Em OpenLDAP sem o overlay `memberOf`, os grupos são procurados por
  `member`/`uniqueMember`.
* **Bloqueio por tentativas** e **Fail2ban** valem igual ao login local. Se o
  AD estiver fora do ar, a tela avisa e a tentativa **não** conta como erro
  (ninguém é bloqueado por causa de uma queda do DC); o evento vai para o
  `auth.log` como `auth.ldap_error`.
* A troca de senha de contas do AD é feita no próprio AD.

## Segurança

* Só **LDAPS** (`ldaps://`, 636) ou **StartTLS** (`ldap://` + StartTLS, 389). LDAP
  sem TLS não existe. O certificado do servidor é validado (CA + nome), TLS 1.2+, a não
  ser que a caixa "Verificar o certificado" seja desmarcada: a conexão continua
  criptografada, mas sem conferir o emissor (a escolha fica na auditoria).
* O `{username}` do filtro é escapado (RFC 4515): `*`, `(`, `)` e `\` digitados
  no login não alteram a busca.
* Senha vazia é recusada antes de chegar ao AD (evita o "bind anônimo" que
  alguns servidores aceitam como sucesso).
* A senha da conta de serviço fica em `credentials` cifrada com AES-256-GCM
  (chave `/etc/openmon/master.key`, AAD com id e tipo da credencial) e nunca
  volta para o navegador. `vault_keys` guarda um HMAC da chave para detectar
  um `master.key` trocado. **Inclua o `master.key` no backup**: sem ele a senha
  da conta de serviço precisa ser digitada de novo.
* Auditoria: `ldap.create`, `ldap.update`, `ldap.delete`, `ldap.test`,
  `user.ldap_provision` e `auth.login` com `source=ldap`.

## Testes com OpenLDAP real

`backend/tests/test_ldap_login.py` roda contra um OpenLDAP com TLS e o
PostgreSQL/TimescaleDB de teste (ver docs/05). Variáveis:
`OPENMON_TEST_LDAP_URL=ldaps://ldap.openmon.test:55636` e
`OPENMON_TEST_LDAP_CA=<ca.pem>`; sem elas os testes são pulados.
