-- =============================================================================
-- OpenMon - Migration 0003: séries temporais (hypertables), continuous
-- aggregates hierárquicos, compressão nativa e retenção de até 5 anos
--
-- Camadas e retenção padrão (ajustáveis em system_settings 'retention.*'):
--
--   metric_samples        bruto (~60 s)      chunk 1 dia     comprime > 2 dias   guarda 35 dias
--   metric_hourly         1 hora             (cagg)          comprime > 7 dias   guarda 25 meses
--   metric_daily          1 dia              (cagg/cagg)     comprime > 45 dias  guarda 62 meses
--
--   interface_samples     bruto (~60 s)      chunk 1 dia     comprime > 2 dias   guarda 35 dias
--   interface_5m          5 minutos (p95)    (cagg)          comprime > 7 dias   guarda 13 meses
--   interface_hourly      1 hora             (cagg/cagg)     comprime > 14 dias  guarda 25 meses
--   interface_daily       1 dia              (cagg/cagg)     comprime > 45 dias  guarda 62 meses
--
-- Buckets em UTC. A cagg diária usa o tenant_id gravado na amostra: se um ativo
-- muda de cliente, o histórico anterior continua com o cliente antigo.
-- As médias são reagregadas por soma/contagem (nunca "média de médias").
-- =============================================================================

SET search_path = openmon, public;

-- -----------------------------------------------------------------------------
-- Métricas de VMs, hosts, datastores, repositórios... (modelo "estreito")
-- 5.000 VMs x ~20 métricas x 1/min ~= 144 M linhas/dia antes da compressão.
-- Sem FKs na hypertable (custo de ingestão); integridade garantida pelo coletor.
-- -----------------------------------------------------------------------------
CREATE TABLE metric_samples (
    time       timestamptz      NOT NULL,
    tenant_id  bigint           NOT NULL,
    asset_id   bigint           NOT NULL,
    metric_id  smallint         NOT NULL,
    value      double precision NOT NULL
);
SELECT create_hypertable('metric_samples', by_range('time', INTERVAL '1 day'));
CREATE INDEX metric_samples_asset_metric_time ON metric_samples (asset_id, metric_id, time DESC);
CREATE INDEX metric_samples_tenant_time ON metric_samples (tenant_id, time DESC);

ALTER TABLE metric_samples SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id, asset_id, metric_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('metric_samples', compress_after => INTERVAL '2 days');
SELECT add_retention_policy('metric_samples', drop_after => INTERVAL '35 days');

-- Agregação horária
CREATE MATERIALIZED VIEW metric_hourly
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '1 hour', time) AS bucket,
       tenant_id,
       asset_id,
       metric_id,
       count(*)    AS samples,
       sum(value)  AS sum_value,
       min(value)  AS min_value,
       max(value)  AS max_value
FROM metric_samples
GROUP BY bucket, tenant_id, asset_id, metric_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_hourly',
    start_offset      => INTERVAL '3 days',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes');
ALTER MATERIALIZED VIEW metric_hourly SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'tenant_id, asset_id, metric_id',
    timescaledb.compress_orderby = 'bucket DESC'
);
SELECT add_compression_policy('metric_hourly', compress_after => INTERVAL '7 days');
SELECT add_retention_policy('metric_hourly', drop_after => INTERVAL '25 months');
CREATE INDEX metric_hourly_asset_metric ON metric_hourly (asset_id, metric_id, bucket DESC);
CREATE INDEX metric_hourly_tenant ON metric_hourly (tenant_id, bucket DESC);

-- Agregação diária (hierárquica, a partir da horária). peak_hour_avg = maior
-- média horária do dia, útil para capacity planning.
CREATE MATERIALIZED VIEW metric_daily
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '1 day', bucket) AS bucket,
       tenant_id,
       asset_id,
       metric_id,
       sum(samples)                AS samples,
       sum(sum_value)              AS sum_value,
       min(min_value)              AS min_value,
       max(max_value)              AS max_value,
       max(sum_value / samples)    AS peak_hour_avg
FROM metric_hourly
GROUP BY 1, tenant_id, asset_id, metric_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metric_daily',
    start_offset      => INTERVAL '7 days',
    end_offset        => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 hour');
ALTER MATERIALIZED VIEW metric_daily SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'tenant_id, asset_id, metric_id',
    timescaledb.compress_orderby = 'bucket DESC'
);
SELECT add_compression_policy('metric_daily', compress_after => INTERVAL '45 days');
SELECT add_retention_policy('metric_daily', drop_after => INTERVAL '62 months');
CREATE INDEX metric_daily_asset_metric ON metric_daily (asset_id, metric_id, bucket DESC);
CREATE INDEX metric_daily_tenant ON metric_daily (tenant_id, bucket DESC);

-- -----------------------------------------------------------------------------
-- Tráfego de interfaces / links (SNMP ifHCInOctets / ifHCOutOctets)
-- O coletor grava o delta de bytes no intervalo e a taxa calculada.
-- -----------------------------------------------------------------------------
CREATE TABLE interface_samples (
    time          timestamptz      NOT NULL,
    tenant_id     bigint           NOT NULL,
    asset_id      bigint           NOT NULL,
    interface_id  bigint           NOT NULL,
    interval_s    real             NOT NULL CHECK (interval_s > 0),
    in_bytes      bigint           NOT NULL CHECK (in_bytes >= 0),
    out_bytes     bigint           NOT NULL CHECK (out_bytes >= 0),
    in_packets    bigint,
    out_packets   bigint,
    in_bps        double precision NOT NULL,
    out_bps       double precision NOT NULL,
    in_errors     integer,
    out_errors    integer,
    in_discards   integer,
    out_discards  integer,
    oper_status   smallint
);
SELECT create_hypertable('interface_samples', by_range('time', INTERVAL '1 day'));
CREATE INDEX interface_samples_if_time ON interface_samples (interface_id, time DESC);
CREATE INDEX interface_samples_tenant_time ON interface_samples (tenant_id, time DESC);

ALTER TABLE interface_samples SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id, interface_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('interface_samples', compress_after => INTERVAL '2 days');
SELECT add_retention_policy('interface_samples', drop_after => INTERVAL '35 days');

-- 5 minutos: base do percentil 95 (padrão de faturamento de banda)
CREATE MATERIALIZED VIEW interface_5m
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '5 minutes', time) AS bucket,
       tenant_id,
       asset_id,
       interface_id,
       sum(interval_s)   AS sum_interval_s,
       sum(in_bytes)     AS in_bytes,
       sum(out_bytes)    AS out_bytes,
       sum(in_packets)   AS in_packets,
       sum(out_packets)  AS out_packets,
       max(in_bps)       AS max_in_bps,
       max(out_bps)      AS max_out_bps,
       sum(in_errors)    AS in_errors,
       sum(out_errors)   AS out_errors,
       sum(in_discards)  AS in_discards,
       sum(out_discards) AS out_discards
FROM interface_samples
GROUP BY bucket, tenant_id, asset_id, interface_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('interface_5m',
    start_offset      => INTERVAL '2 days',
    end_offset        => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes');
ALTER MATERIALIZED VIEW interface_5m SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'tenant_id, interface_id',
    timescaledb.compress_orderby = 'bucket DESC'
);
SELECT add_compression_policy('interface_5m', compress_after => INTERVAL '7 days');
SELECT add_retention_policy('interface_5m', drop_after => INTERVAL '13 months');
CREATE INDEX interface_5m_if ON interface_5m (interface_id, bucket DESC);
CREATE INDEX interface_5m_tenant ON interface_5m (tenant_id, bucket DESC);

-- Horária (a partir da de 5 min). peak_5m_*_bps = maior média de 5 min da hora.
CREATE MATERIALIZED VIEW interface_hourly
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '1 hour', bucket) AS bucket,
       tenant_id,
       asset_id,
       interface_id,
       sum(sum_interval_s)                          AS sum_interval_s,
       sum(in_bytes)                                AS in_bytes,
       sum(out_bytes)                               AS out_bytes,
       sum(in_packets)                              AS in_packets,
       sum(out_packets)                             AS out_packets,
       max(in_bytes * 8 / sum_interval_s)           AS peak_5m_in_bps,
       max(out_bytes * 8 / sum_interval_s)          AS peak_5m_out_bps,
       sum(in_errors)                               AS in_errors,
       sum(out_errors)                              AS out_errors
FROM interface_5m
GROUP BY 1, tenant_id, asset_id, interface_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('interface_hourly',
    start_offset      => INTERVAL '3 days',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes');
ALTER MATERIALIZED VIEW interface_hourly SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'tenant_id, interface_id',
    timescaledb.compress_orderby = 'bucket DESC'
);
SELECT add_compression_policy('interface_hourly', compress_after => INTERVAL '14 days');
SELECT add_retention_policy('interface_hourly', drop_after => INTERVAL '25 months');
CREATE INDEX interface_hourly_if ON interface_hourly (interface_id, bucket DESC);
CREATE INDEX interface_hourly_tenant ON interface_hourly (tenant_id, bucket DESC);

-- Diária (a partir da horária): volume transferido e pico do dia
CREATE MATERIALIZED VIEW interface_daily
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '1 day', bucket) AS bucket,
       tenant_id,
       asset_id,
       interface_id,
       sum(sum_interval_s)    AS sum_interval_s,
       sum(in_bytes)          AS in_bytes,
       sum(out_bytes)         AS out_bytes,
       sum(in_packets)        AS in_packets,
       sum(out_packets)       AS out_packets,
       max(peak_5m_in_bps)    AS peak_5m_in_bps,
       max(peak_5m_out_bps)   AS peak_5m_out_bps,
       sum(in_errors)         AS in_errors,
       sum(out_errors)        AS out_errors
FROM interface_hourly
GROUP BY 1, tenant_id, asset_id, interface_id
WITH NO DATA;

SELECT add_continuous_aggregate_policy('interface_daily',
    start_offset      => INTERVAL '7 days',
    end_offset        => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 hour');
ALTER MATERIALIZED VIEW interface_daily SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'tenant_id, interface_id',
    timescaledb.compress_orderby = 'bucket DESC'
);
SELECT add_compression_policy('interface_daily', compress_after => INTERVAL '45 days');
SELECT add_retention_policy('interface_daily', drop_after => INTERVAL '62 months');
CREATE INDEX interface_daily_if ON interface_daily (interface_id, bucket DESC);
CREATE INDEX interface_daily_tenant ON interface_daily (tenant_id, bucket DESC);

-- -----------------------------------------------------------------------------
-- Retenção configurável pela interface (Admin Global)
-- -----------------------------------------------------------------------------
INSERT INTO system_settings (key, value) VALUES
    ('retention.metric_samples',    '"35 days"'),
    ('retention.metric_hourly',     '"25 months"'),
    ('retention.metric_daily',      '"62 months"'),
    ('retention.interface_samples', '"35 days"'),
    ('retention.interface_5m',      '"13 months"'),
    ('retention.interface_hourly',  '"25 months"'),
    ('retention.interface_daily',   '"62 months"');

-- Reaplica as políticas de retenção a partir de system_settings. Valida limites
-- mínimos para que nenhuma camada apague dados antes de a camada seguinte os
-- ter agregado (retenção > janela de refresh da cagg filha).
CREATE FUNCTION apply_retention_settings()
RETURNS TABLE (relation text, drop_after interval)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = openmon, public, pg_temp
AS $$
DECLARE
    r       record;
    v_iv    interval;
    minimum CONSTANT jsonb := '{
        "metric_samples": "7 days",   "metric_hourly": "90 days",   "metric_daily": "12 months",
        "interface_samples": "7 days", "interface_5m": "35 days",   "interface_hourly": "90 days",
        "interface_daily": "12 months"}';
BEGIN
    IF NOT openmon.ctx_is_global() THEN
        RAISE EXCEPTION 'apenas o contexto global pode alterar a retenção' USING ERRCODE = '42501';
    END IF;
    FOR r IN
        SELECT substr(s.key, length('retention.') + 1) AS rel, s.value #>> '{}' AS val
        FROM system_settings s
        WHERE s.key LIKE 'retention.%'
    LOOP
        IF NOT minimum ? r.rel THEN
            RAISE EXCEPTION 'retenção desconhecida: %', r.rel;
        END IF;
        v_iv := r.val::interval;
        IF v_iv < (minimum ->> r.rel)::interval THEN
            RAISE EXCEPTION 'retenção de % (%) abaixo do mínimo permitido (%)', r.rel, v_iv, minimum ->> r.rel;
        END IF;
        PERFORM remove_retention_policy(format('openmon.%I', r.rel)::regclass, if_exists => true);
        PERFORM add_retention_policy(format('openmon.%I', r.rel)::regclass, drop_after => v_iv);
        relation := r.rel;
        drop_after := v_iv;
        RETURN NEXT;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION apply_retention_settings() FROM PUBLIC;
