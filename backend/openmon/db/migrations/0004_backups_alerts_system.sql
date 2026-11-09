-- =============================================================================
-- OpenMon - Migration 0004: Veeam, alertas/notificações e backup do próprio OpenMon
-- =============================================================================

SET search_path = openmon, public;

-- -----------------------------------------------------------------------------
-- Veeam Backup & Replication / Enterprise Manager
-- Volume baixo (algumas mil sessões/dia): tabela relacional com RLS em vez de
-- hypertable, o que permite upsert do status da sessão em andamento.
-- -----------------------------------------------------------------------------
CREATE TABLE backup_jobs (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id         bigint      NOT NULL REFERENCES tenants (id),
    integration_id    bigint      NOT NULL REFERENCES integrations (id) ON DELETE CASCADE,
    external_id       text        NOT NULL,
    name              text        NOT NULL,
    job_type          text,        -- Backup, BackupCopy, Replica, Agent...
    is_enabled        boolean     NOT NULL DEFAULT true,
    schedule_desc     text,
    sla_rpo_hours     integer     CHECK (sla_rpo_hours > 0),  -- NULL = usa tenants.backup_sla_hours
    repository_id     bigint      REFERENCES assets (id) ON DELETE SET NULL,
    last_result       text        CHECK (last_result IN ('success', 'warning', 'failed', 'running', 'canceled', 'none')),
    last_run_at       timestamptz,
    last_success_at   timestamptz,
    tenant_locked     boolean     NOT NULL DEFAULT false,
    deleted_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT backup_jobs_external_uq UNIQUE (integration_id, external_id)
);
CREATE INDEX backup_jobs_tenant_idx ON backup_jobs (tenant_id) WHERE deleted_at IS NULL;

CREATE TABLE backup_job_runs (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id            bigint      NOT NULL REFERENCES tenants (id),
    job_id               bigint      NOT NULL REFERENCES backup_jobs (id) ON DELETE CASCADE,
    session_external_id  text        NOT NULL,
    started_at           timestamptz NOT NULL,
    ended_at             timestamptz,
    result               text        NOT NULL CHECK (result IN ('success', 'warning', 'failed', 'running', 'canceled')),
    duration_s           integer,
    processed_bytes      bigint,
    read_bytes           bigint,
    transferred_bytes    bigint,
    backup_size_bytes    bigint,
    objects_total        integer,
    objects_failed       integer,
    message              text,
    CONSTRAINT backup_job_runs_session_uq UNIQUE (job_id, session_external_id)
);
CREATE INDEX backup_job_runs_tenant_time ON backup_job_runs (tenant_id, started_at DESC);
CREATE INDEX backup_job_runs_job_time ON backup_job_runs (job_id, started_at DESC);

-- -----------------------------------------------------------------------------
-- Canais de notificação (e-mail SMTP TLS/STARTTLS, Telegram, Webhook).
-- Segredos (senha SMTP, token do bot, segredo HMAC do webhook) ficam no cofre.
-- -----------------------------------------------------------------------------
CREATE TABLE notification_channels (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      bigint      REFERENCES tenants (id) ON DELETE CASCADE,   -- NULL = canal global (NOC)
    kind           text        NOT NULL CHECK (kind IN ('email', 'telegram', 'webhook')),
    name           text        NOT NULL,
    -- email: {"host","port","security":"starttls|tls","from","to":[...]}
    -- telegram: {"chat_id": "-100..."}  webhook: {"url","method","headers":{}}
    config         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    credential_id  uuid        REFERENCES credentials (id) ON DELETE RESTRICT,
    is_enabled     boolean     NOT NULL DEFAULT true,
    last_test_at   timestamptz,
    last_test_ok   boolean,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_channels_name_uq UNIQUE NULLS NOT DISTINCT (tenant_id, name)
);

-- Triggers / limiares. Escopo: um ativo, um tipo de ativo de um tenant, ou global.
CREATE TABLE alert_triggers (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id         bigint      REFERENCES tenants (id) ON DELETE CASCADE,   -- NULL = todos os tenants
    name              text        NOT NULL,
    asset_id          bigint      REFERENCES assets (id) ON DELETE CASCADE,
    interface_id      bigint      REFERENCES interfaces (id) ON DELETE CASCADE,
    asset_type        text,
    source            text        NOT NULL CHECK (source IN ('metric', 'interface', 'backup', 'availability', 'integration')),
    metric_id         smallint    REFERENCES metric_definitions (id),
    expression        text        NOT NULL DEFAULT 'avg' CHECK (expression IN ('last', 'avg', 'min', 'max')),
    operator          text        NOT NULL CHECK (operator IN ('>', '>=', '<', '<=', '=', '<>')),
    threshold         double precision NOT NULL,
    recovery_threshold double precision,   -- histerese
    window_seconds    integer     NOT NULL DEFAULT 300 CHECK (window_seconds BETWEEN 60 AND 86400),
    severity          text        NOT NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    is_enabled        boolean     NOT NULL DEFAULT true,
    created_by        bigint      REFERENCES users (id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alert_triggers_target CHECK (num_nonnulls(asset_id, interface_id, asset_type) <= 1)
);
CREATE INDEX alert_triggers_tenant_idx ON alert_triggers (tenant_id) WHERE is_enabled;

CREATE TABLE alert_trigger_channels (
    trigger_id  bigint NOT NULL REFERENCES alert_triggers (id) ON DELETE CASCADE,
    channel_id  bigint NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    PRIMARY KEY (trigger_id, channel_id)
);

CREATE TABLE alert_problems (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id        bigint      NOT NULL REFERENCES tenants (id),
    trigger_id       bigint      REFERENCES alert_triggers (id) ON DELETE SET NULL,
    asset_id         bigint      REFERENCES assets (id) ON DELETE SET NULL,
    interface_id     bigint      REFERENCES interfaces (id) ON DELETE SET NULL,
    severity         text        NOT NULL,
    status           text        NOT NULL DEFAULT 'problem' CHECK (status IN ('problem', 'resolved')),
    opened_at        timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz,
    acknowledged_at  timestamptz,
    acknowledged_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    ack_comment      text,
    value            double precision,
    message          text        NOT NULL
);
CREATE INDEX alert_problems_open_idx ON alert_problems (tenant_id, severity) WHERE status = 'problem';
CREATE INDEX alert_problems_tenant_time ON alert_problems (tenant_id, opened_at DESC);
-- No máximo um problema aberto por trigger + ativo/interface
CREATE UNIQUE INDEX alert_problems_one_open ON alert_problems (trigger_id, coalesce(asset_id, 0), coalesce(interface_id, 0))
    WHERE status = 'problem';

CREATE TABLE notification_deliveries (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    bigint      REFERENCES tenants (id) ON DELETE CASCADE,
    problem_id   bigint      REFERENCES alert_problems (id) ON DELETE CASCADE,
    channel_id   bigint      REFERENCES notification_channels (id) ON DELETE SET NULL,
    event        text        NOT NULL CHECK (event IN ('problem', 'recovery', 'ack', 'test')),
    status       text        NOT NULL CHECK (status IN ('queued', 'sent', 'failed')),
    attempts     smallint    NOT NULL DEFAULT 0,
    last_error   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz
);
CREATE INDEX notification_deliveries_queue ON notification_deliveries (created_at) WHERE status = 'queued';

-- -----------------------------------------------------------------------------
-- Backup e restauração do próprio OpenMon (somente Admin Global)
-- -----------------------------------------------------------------------------
CREATE TABLE system_backup_policy (
    id                  smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    is_enabled          boolean     NOT NULL DEFAULT true,
    on_calendar         text        NOT NULL DEFAULT '*-*-* 02:30:00',  -- sintaxe systemd OnCalendar
    keep_last           integer     NOT NULL DEFAULT 14 CHECK (keep_last BETWEEN 1 AND 365),
    include_timeseries  boolean     NOT NULL DEFAULT false,  -- dump completo das hypertables (grande)
    target_dir          text        NOT NULL DEFAULT '/var/backups/openmon',
    updated_at          timestamptz NOT NULL DEFAULT now(),
    updated_by          bigint      REFERENCES users (id) ON DELETE SET NULL
);
INSERT INTO system_backup_policy (id) VALUES (1);

CREATE TABLE system_backups (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind                text        NOT NULL CHECK (kind IN ('scheduled', 'manual', 'pre_restore')),
    status              text        NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    file_name           text        CHECK (file_name ~ '^openmon_[0-9]{8}T[0-9]{6}Z_[a-z_]+\.tar\.zst$'),
    size_bytes          bigint,
    sha256              bytea       CHECK (sha256 IS NULL OR octet_length(sha256) = 32),
    includes_timeseries boolean     NOT NULL DEFAULT false,
    pg_version          text,
    timescaledb_version text,
    app_version         text,
    created_by          bigint      REFERENCES users (id) ON DELETE SET NULL,
    message             text
);

CREATE TABLE system_restores (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    backup_id     bigint      NOT NULL REFERENCES system_backups (id),
    pre_backup_id bigint      REFERENCES system_backups (id),  -- backup automático feito antes de restaurar
    status        text        NOT NULL CHECK (status IN ('pending', 'running', 'ok', 'failed')),
    requested_by  bigint      REFERENCES users (id) ON DELETE SET NULL,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    message       text
);
