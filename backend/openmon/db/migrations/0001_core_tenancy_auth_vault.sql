-- =============================================================================
-- OpenMon - Migration 0001: núcleo, multi-tenancy, RBAC, LDAP, cofre e auditoria
-- Alvo: PostgreSQL 17 + TimescaleDB 2.13+ (Debian 13 Trixie ou superior)
--
-- Executada pelo deployer com SET ROLE openmon_owner, dentro de uma transação.
-- A extensão timescaledb e o schema "openmon" já foram criados pelo deployer
-- (CREATE EXTENSION exige superusuário).
-- =============================================================================

SET search_path = openmon, public;

-- -----------------------------------------------------------------------------
-- Tenants (grupos de clientes). Existe exatamente um tenant "provedor", dono da
-- infraestrutura compartilhada do datacenter (core, vCenters, Veeam...).
-- -----------------------------------------------------------------------------
CREATE TABLE tenants (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    slug              text        NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name              text        NOT NULL,
    is_provider       boolean     NOT NULL DEFAULT false,
    is_active         boolean     NOT NULL DEFAULT true,
    contact_email     text,
    backup_sla_hours  integer     CHECK (backup_sla_hours > 0),   -- RPO contratado (Veeam)
    notes             text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tenants_single_provider ON tenants (is_provider) WHERE is_provider;

-- -----------------------------------------------------------------------------
-- Cofre de credenciais (AES-256-GCM, chave mestra em /etc/openmon/master.key)
-- O banco guarda apenas nonce + ciphertext(+tag). A cifragem acontece na VM 1.
-- AAD usada pela aplicação: 'openmon:cred:v1:' || id || ':' || kind
-- -----------------------------------------------------------------------------
CREATE TABLE vault_keys (
    version     smallint    PRIMARY KEY CHECK (version > 0),
    -- HMAC-SHA256(chave, 'openmon-key-check'): confirma que o arquivo de chave
    -- carregado é o correto sem nunca expor a chave.
    key_check   bytea       NOT NULL CHECK (octet_length(key_check) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz
);

CREATE TABLE credentials (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    bigint      REFERENCES tenants (id) ON DELETE CASCADE,  -- NULL = global
    name         text        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN (
                     'ssh_password', 'ssh_private_key', 'vmware', 'winrm', 'veeam',
                     'ldap_bind', 'snmp_v2c', 'snmp_v3', 'smtp', 'telegram_bot',
                     'webhook', 'generic')),
    username     text,                       -- não secreto
    params       jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- não secreto (ex.: auth_proto SNMPv3)
    key_version  smallint    NOT NULL REFERENCES vault_keys (version),
    nonce        bytea       NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext   bytea       NOT NULL CHECK (octet_length(ciphertext) >= 17),  -- dados + tag de 16 bytes
    created_by   bigint,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    rotated_at   timestamptz,
    CONSTRAINT credentials_name_uq UNIQUE NULLS NOT DISTINCT (tenant_id, name)
);
CREATE INDEX credentials_tenant_idx ON credentials (tenant_id);
CREATE INDEX credentials_key_version_idx ON credentials (key_version);

-- -----------------------------------------------------------------------------
-- RBAC
--   scope = 'global' -> enxerga todos os tenants (Admin Global, Operador NOC)
--   scope = 'tenant' -> enxerga apenas os tenants vinculados (Cliente)
-- -----------------------------------------------------------------------------
CREATE TABLE roles (
    id           smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code         text     NOT NULL UNIQUE CHECK (code ~ '^[a-z][a-z0-9_]{1,40}$'),
    name         text     NOT NULL,
    scope        text     NOT NULL CHECK (scope IN ('global', 'tenant')),
    is_builtin   boolean  NOT NULL DEFAULT false,
    description  text
);

CREATE TABLE permissions (
    code         text PRIMARY KEY CHECK (code ~ '^[a-z][a-z0-9_.]{1,80}$'),
    description  text NOT NULL
);

CREATE TABLE role_permissions (
    role_id          smallint NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_code  text     NOT NULL REFERENCES permissions (code) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_code)
);

-- -----------------------------------------------------------------------------
-- Active Directory (LDAPS / StartTLS). LDAP sem TLS não é aceito.
-- -----------------------------------------------------------------------------
CREATE TABLE ldap_directories (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                text        NOT NULL UNIQUE,
    is_enabled          boolean     NOT NULL DEFAULT true,
    urls                text[]      NOT NULL CHECK (cardinality(urls) > 0),   -- ldaps://dc1.local:636
    security            text        NOT NULL DEFAULT 'ldaps' CHECK (security IN ('ldaps', 'starttls')),
    base_dn             text        NOT NULL,
    bind_credential_id  uuid        REFERENCES credentials (id) ON DELETE RESTRICT,
    user_filter         text        NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))',
    group_attribute     text        NOT NULL DEFAULT 'memberOf',
    ca_cert_pem         text,
    timeout_seconds     smallint    NOT NULL DEFAULT 5 CHECK (timeout_seconds BETWEEN 1 AND 60),
    default_role_id     smallint    REFERENCES roles (id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Grupo do AD -> perfil + tenant. Um usuário do AD herda o mapeamento de maior prioridade.
CREATE TABLE ldap_group_mappings (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    directory_id  bigint   NOT NULL REFERENCES ldap_directories (id) ON DELETE CASCADE,
    group_dn      text     NOT NULL,
    role_id       smallint NOT NULL REFERENCES roles (id),
    tenant_id     bigint   REFERENCES tenants (id) ON DELETE CASCADE,  -- NULL para perfis globais
    priority      integer  NOT NULL DEFAULT 100,
    CONSTRAINT ldap_group_mappings_uq UNIQUE NULLS NOT DISTINCT (directory_id, group_dn, tenant_id)
);

-- -----------------------------------------------------------------------------
-- Usuários
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username              text        NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
    display_name          text,
    email                 text,
    auth_source           text        NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'ldap')),
    ldap_directory_id     bigint      REFERENCES ldap_directories (id) ON DELETE SET NULL,
    external_dn           text,
    -- String PHC do Argon2id ($argon2id$...) ou Bcrypt ($2b$...). Nunca texto puro.
    password_hash         text,
    role_id               smallint    NOT NULL REFERENCES roles (id),
    is_active             boolean     NOT NULL DEFAULT true,
    must_change_password  boolean     NOT NULL DEFAULT false,
    failed_login_count    integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    last_login_ip         inet,
    password_changed_at   timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_local_has_hash CHECK (auth_source <> 'local' OR password_hash IS NOT NULL),
    CONSTRAINT users_hash_format CHECK (password_hash IS NULL OR password_hash ~ '^\$(argon2id|2[aby])\$')
);
CREATE UNIQUE INDEX users_username_uq ON users (lower(username));

-- Tenants que um usuário de escopo 'tenant' pode ver
CREATE TABLE user_tenants (
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id  bigint NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX user_tenants_tenant_idx ON user_tenants (tenant_id);

ALTER TABLE credentials
    ADD CONSTRAINT credentials_created_by_fk FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL;

-- Sessões do servidor: guardamos só o SHA-256 do token e do token CSRF.
CREATE TABLE user_sessions (
    token_hash       bytea       PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id          bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token_hash  bytea       NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    auth_source      text        NOT NULL CHECK (auth_source IN ('local', 'ldap')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    client_ip        inet,
    user_agent       text,
    revoked_at       timestamptz
);
CREATE INDEX user_sessions_user_idx ON user_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX user_sessions_expires_idx ON user_sessions (expires_at);

-- -----------------------------------------------------------------------------
-- Tentativas de login (rate limiting / brute force). O espelho em texto vai
-- para /var/log/openmon/auth.log (Fail2ban).
-- -----------------------------------------------------------------------------
CREATE TABLE login_attempts (
    time        timestamptz NOT NULL DEFAULT now(),
    username    text        NOT NULL,
    client_ip   inet        NOT NULL,
    success     boolean     NOT NULL,
    reason      text,
    auth_source text
);
SELECT create_hypertable('login_attempts', by_range('time', INTERVAL '7 days'));
CREATE INDEX login_attempts_ip_time ON login_attempts (client_ip, time DESC);
CREATE INDEX login_attempts_user_time ON login_attempts (lower(username), time DESC);
SELECT add_retention_policy('login_attempts', drop_after => INTERVAL '180 days');

-- -----------------------------------------------------------------------------
-- Trilha de auditoria (append-only: a aplicação só tem INSERT).
-- -----------------------------------------------------------------------------
CREATE TABLE audit_log (
    time         timestamptz NOT NULL DEFAULT now(),
    event_id     uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id    bigint,
    user_id      bigint,
    username     text,
    client_ip    inet,
    user_agent   text,
    action       text        NOT NULL,            -- ex.: credential.create, asset.update, auth.login
    object_type  text,
    object_id    text,
    outcome      text        NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied')),
    details      jsonb       NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('audit_log', by_range('time', INTERVAL '30 days'));
CREATE INDEX audit_log_tenant_time ON audit_log (tenant_id, time DESC);
CREATE INDEX audit_log_user_time ON audit_log (user_id, time DESC);
CREATE INDEX audit_log_action_time ON audit_log (action, time DESC);
ALTER TABLE audit_log SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('audit_log', compress_after => INTERVAL '60 days');
SELECT add_retention_policy('audit_log', drop_after => INTERVAL '62 months');

-- -----------------------------------------------------------------------------
-- Configurações gerais (chave/valor)
-- -----------------------------------------------------------------------------
CREATE TABLE system_settings (
    key         text        PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{1,100}$'),
    value       jsonb       NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  bigint      REFERENCES users (id) ON DELETE SET NULL
);

-- -----------------------------------------------------------------------------
-- Dados iniciais (sem usuário padrão: o admin é criado pelo instalador com
-- senha aleatória exibida uma única vez).
-- -----------------------------------------------------------------------------
INSERT INTO tenants (slug, name, is_provider) VALUES ('datacenter', 'Datacenter (Provedor)', true);

INSERT INTO roles (code, name, scope, is_builtin, description) VALUES
    ('global_admin', 'Administrador Global do Datacenter', 'global', true, 'Acesso total a todos os tenants e à configuração do sistema'),
    ('operator',     'Operador',                           'global', true, 'Opera monitoramento e alertas de todos os tenants, sem administrar o sistema'),
    ('client',       'Cliente',                            'tenant', true, 'Visualiza somente os ativos e relatórios dos seus tenants');

INSERT INTO permissions (code, description) VALUES
    ('dashboard.view',        'Ver dashboards e métricas'),
    ('assets.view',           'Ver ativos'),
    ('assets.manage',         'Criar, editar e remover ativos'),
    ('integrations.manage',   'Gerenciar integrações (vCenter, Hyper-V, Veeam, SNMP)'),
    ('credentials.manage',    'Gerenciar o cofre de credenciais'),
    ('alerts.view',           'Ver alertas'),
    ('alerts.ack',            'Reconhecer alertas'),
    ('alerts.manage',         'Gerenciar triggers e canais de notificação'),
    ('backups.view',          'Ver status de backups Veeam'),
    ('reports.view',          'Gerar e exportar relatórios'),
    ('tenants.manage',        'Gerenciar tenants'),
    ('users.manage',          'Gerenciar usuários, perfis e LDAP'),
    ('audit.view',            'Consultar a trilha de auditoria'),
    ('system.backup',         'Backup e restauração do OpenMon'),
    ('system.settings',       'Configurações do sistema e deploy do banco');

INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, p.code FROM roles r CROSS JOIN permissions p WHERE r.code = 'global_admin';

INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
    'dashboard.view', 'assets.view', 'assets.manage', 'alerts.view', 'alerts.ack',
    'alerts.manage', 'backups.view', 'reports.view', 'audit.view')
WHERE r.code = 'operator';

INSERT INTO role_permissions (role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
    'dashboard.view', 'assets.view', 'alerts.view', 'backups.view', 'reports.view')
WHERE r.code = 'client';

INSERT INTO system_settings (key, value) VALUES
    ('auth.lockout', '{"max_failures": 5, "window_minutes": 15, "lock_minutes": 15}'),
    ('auth.session', '{"idle_minutes": 30, "absolute_hours": 12}'),
    ('auth.password_policy', '{"min_length": 12, "hash": "argon2id"}');
