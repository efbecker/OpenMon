-- =============================================================================
-- OpenMon - Migration 0005: isolamento de tenants (RLS), views seguras e GRANTs
--
-- Modelo de acesso:
--   * openmon_owner  dono dos objetos, roda migrations (nunca usado pela API)
--   * openmon_app    papel da aplicação (API e coletores), sem DDL, sem BYPASSRLS
--
-- A cada transação a aplicação chama:
--     SELECT openmon.set_request_context(:user_id, :is_global, :tenant_ids);
-- Os valores valem só até o fim da transação (set_config local). Sem contexto,
-- nenhuma linha de dado de tenant é visível (fail-closed). Isto é a segunda
-- barreira contra IDOR; a primeira é a validação de tenant no backend.
--
-- Tabelas relacionais: Row-Level Security.
-- Hypertables e continuous aggregates: o TimescaleDB não permite RLS em tabelas
-- com compressão, então a aplicação só tem INSERT nelas e lê pelas views v_*,
-- que aplicam o mesmo filtro (security_barrier).
-- =============================================================================

SET search_path = openmon, public;

-- -----------------------------------------------------------------------------
-- Contexto da requisição
-- -----------------------------------------------------------------------------
CREATE FUNCTION ctx_is_global() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT coalesce(current_setting('openmon.is_global', true), '') = 'on' $$;

CREATE FUNCTION ctx_user_id() RETURNS bigint
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT nullif(current_setting('openmon.user_id', true), '')::bigint $$;

CREATE FUNCTION ctx_tenant_ids() RETURNS bigint[]
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT coalesce(string_to_array(nullif(current_setting('openmon.tenant_ids', true), ''), ',')::bigint[], '{}'::bigint[]) $$;

CREATE FUNCTION tenant_visible(p_tenant_id bigint) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT openmon.ctx_is_global() OR p_tenant_id = ANY (openmon.ctx_tenant_ids()) $$;

CREATE FUNCTION set_request_context(p_user_id bigint, p_is_global boolean, p_tenant_ids bigint[])
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM set_config('openmon.user_id', coalesce(p_user_id::text, ''), true);
    PERFORM set_config('openmon.is_global', CASE WHEN p_is_global THEN 'on' ELSE 'off' END, true);
    PERFORM set_config('openmon.tenant_ids', coalesce(array_to_string(p_tenant_ids, ','), ''), true);
END;
$$;

-- -----------------------------------------------------------------------------
-- RLS: tabelas por tenant
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'credentials', 'integrations', 'assets', 'interfaces', 'user_tenants',
        'backup_jobs', 'backup_job_runs', 'notification_channels', 'alert_triggers',
        'alert_problems', 'notification_deliveries']
    LOOP
        EXECUTE format('ALTER TABLE openmon.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON openmon.%I USING (openmon.tenant_visible(tenant_id)) '
            'WITH CHECK (openmon.tenant_visible(tenant_id))', t);
    END LOOP;
END $$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (tenant_visible(id))
    WITH CHECK (ctx_is_global());

-- Usuário enxerga a si mesmo; admin vê todos; cliente vê usuários dos seus tenants
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (ctx_is_global()
           OR id = ctx_user_id()
           OR EXISTS (SELECT 1 FROM user_tenants ut WHERE ut.user_id = users.id))
    WITH CHECK (ctx_is_global() OR id = ctx_user_id());

-- Filhas sem tenant_id próprio herdam do pai
ALTER TABLE snmp_targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON snmp_targets
    USING (EXISTS (SELECT 1 FROM assets a WHERE a.id = snmp_targets.asset_id))
    WITH CHECK (EXISTS (SELECT 1 FROM assets a WHERE a.id = snmp_targets.asset_id));

ALTER TABLE interface_counter_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON interface_counter_state
    USING (EXISTS (SELECT 1 FROM interfaces i WHERE i.id = interface_counter_state.interface_id))
    WITH CHECK (EXISTS (SELECT 1 FROM interfaces i WHERE i.id = interface_counter_state.interface_id));

ALTER TABLE alert_trigger_channels ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON alert_trigger_channels
    USING (EXISTS (SELECT 1 FROM alert_triggers t WHERE t.id = alert_trigger_channels.trigger_id))
    WITH CHECK (EXISTS (SELECT 1 FROM alert_triggers t WHERE t.id = alert_trigger_channels.trigger_id));

-- -----------------------------------------------------------------------------
-- RLS: tabelas exclusivas do contexto global (admin, workers, autenticação)
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'vault_keys', 'ldap_directories', 'ldap_group_mappings', 'user_sessions',
        'system_settings', 'tenant_assignment_rules', 'system_backup_policy',
        'system_backups', 'system_restores']
    LOOP
        EXECUTE format('ALTER TABLE openmon.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY global_only ON openmon.%I USING (openmon.ctx_is_global()) '
            'WITH CHECK (openmon.ctx_is_global())', t);
    END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- Views de leitura das séries temporais (filtro de tenant obrigatório)
-- -----------------------------------------------------------------------------
CREATE VIEW v_metric_samples WITH (security_barrier = true) AS
SELECT time, tenant_id, asset_id, metric_id, value
FROM metric_samples
WHERE tenant_visible(tenant_id);

CREATE VIEW v_metric_hourly WITH (security_barrier = true) AS
SELECT bucket, tenant_id, asset_id, metric_id, samples,
       sum_value / nullif(samples, 0) AS avg_value, min_value, max_value
FROM metric_hourly
WHERE tenant_visible(tenant_id);

CREATE VIEW v_metric_daily WITH (security_barrier = true) AS
SELECT bucket, tenant_id, asset_id, metric_id, samples,
       sum_value / nullif(samples, 0) AS avg_value, min_value, max_value, peak_hour_avg
FROM metric_daily
WHERE tenant_visible(tenant_id);

CREATE VIEW v_interface_samples WITH (security_barrier = true) AS
SELECT time, tenant_id, asset_id, interface_id, interval_s, in_bytes, out_bytes,
       in_packets, out_packets, in_bps, out_bps, in_errors, out_errors,
       in_discards, out_discards, oper_status
FROM interface_samples
WHERE tenant_visible(tenant_id);

CREATE VIEW v_interface_5m WITH (security_barrier = true) AS
SELECT bucket, tenant_id, asset_id, interface_id, in_bytes, out_bytes,
       in_bytes  * 8 / nullif(sum_interval_s, 0) AS in_bps,
       out_bytes * 8 / nullif(sum_interval_s, 0) AS out_bps,
       in_packets / nullif(sum_interval_s, 0)    AS in_pps,
       out_packets / nullif(sum_interval_s, 0)   AS out_pps,
       max_in_bps, max_out_bps, in_errors, out_errors, in_discards, out_discards
FROM interface_5m
WHERE tenant_visible(tenant_id);

CREATE VIEW v_interface_hourly WITH (security_barrier = true) AS
SELECT bucket, tenant_id, asset_id, interface_id, in_bytes, out_bytes,
       in_bytes  * 8 / nullif(sum_interval_s, 0) AS in_bps,
       out_bytes * 8 / nullif(sum_interval_s, 0) AS out_bps,
       in_packets / nullif(sum_interval_s, 0)    AS in_pps,
       out_packets / nullif(sum_interval_s, 0)   AS out_pps,
       peak_5m_in_bps, peak_5m_out_bps, in_errors, out_errors
FROM interface_hourly
WHERE tenant_visible(tenant_id);

CREATE VIEW v_interface_daily WITH (security_barrier = true) AS
SELECT bucket, tenant_id, asset_id, interface_id, in_bytes, out_bytes,
       in_bytes  * 8 / nullif(sum_interval_s, 0) AS in_bps,
       out_bytes * 8 / nullif(sum_interval_s, 0) AS out_bps,
       peak_5m_in_bps, peak_5m_out_bps, in_errors, out_errors
FROM interface_daily
WHERE tenant_visible(tenant_id);

CREATE VIEW v_audit_log WITH (security_barrier = true) AS
SELECT time, event_id, tenant_id, user_id, username, client_ip, user_agent,
       action, object_type, object_id, outcome, details
FROM audit_log
WHERE ctx_is_global() OR tenant_visible(tenant_id);

-- Percentil 95 de um link no período (amostras de 5 min; até 13 meses).
-- SECURITY DEFINER para ler a cagg diretamente; o filtro de tenant do contexto
-- da requisição é aplicado explicitamente.
CREATE FUNCTION interface_p95(p_interface_id bigint, p_from timestamptz, p_to timestamptz)
RETURNS TABLE (in_p95_bps double precision, out_p95_bps double precision,
               in_bytes numeric, out_bytes numeric, samples bigint)
LANGUAGE sql STABLE
SECURITY DEFINER
SET search_path = openmon, public, pg_temp
AS $$
    SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY f.in_bytes  * 8 / f.sum_interval_s),
           percentile_cont(0.95) WITHIN GROUP (ORDER BY f.out_bytes * 8 / f.sum_interval_s),
           sum(f.in_bytes), sum(f.out_bytes), count(*)
    FROM openmon.interface_5m f
    WHERE f.interface_id = p_interface_id
      AND f.bucket >= p_from AND f.bucket < p_to
      AND f.sum_interval_s > 0
      AND openmon.tenant_visible(f.tenant_id)
$$;

-- -----------------------------------------------------------------------------
-- Privilégios
-- -----------------------------------------------------------------------------
REVOKE ALL ON SCHEMA openmon FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA openmon FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openmon FROM PUBLIC;
GRANT USAGE ON SCHEMA openmon TO openmon_app;

-- Relacionais: DML completo (o RLS restringe as linhas)
GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenants, credentials, roles, role_permissions, ldap_directories, ldap_group_mappings,
    users, user_tenants, user_sessions, system_settings, integrations, assets,
    tenant_assignment_rules, snmp_targets, interfaces, interface_counter_state,
    backup_jobs, backup_job_runs, notification_channels, alert_triggers,
    alert_trigger_channels, alert_problems, notification_deliveries,
    system_backup_policy, system_backups, system_restores
TO openmon_app;

-- Somente leitura / append-only
GRANT SELECT ON permissions, metric_definitions, schema_migrations TO openmon_app;
GRANT SELECT, INSERT ON vault_keys TO openmon_app;
GRANT SELECT, INSERT ON login_attempts TO openmon_app;
GRANT INSERT ON audit_log, metric_samples, interface_samples TO openmon_app;

GRANT SELECT ON v_metric_samples, v_metric_hourly, v_metric_daily, v_interface_samples,
    v_interface_5m, v_interface_hourly, v_interface_daily, v_audit_log
TO openmon_app;

GRANT EXECUTE ON FUNCTION ctx_is_global(), ctx_user_id(), ctx_tenant_ids(), tenant_visible(bigint),
    set_request_context(bigint, boolean, bigint[]), interface_p95(bigint, timestamptz, timestamptz),
    apply_retention_settings()
TO openmon_app;
