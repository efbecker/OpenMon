-- =============================================================================
-- OpenMon - Migration 0007: alertas de disco das VMs ligados de fábrica
--
-- A tela VMs pinta a VM de "atenção" com um volume acima de 90% e de "crítico" acima de 97%.
-- Estes dois alertas (para todos os tenants) abrem o problema correspondente, para que o
-- status da VM, os Problemas ativos e as notificações venham da mesma regra. O admin pode
-- editar ou desligar em Alertas > Configurar; a migration só cria se ainda não houver um
-- alerta global com o mesmo nome.
-- =============================================================================

SET search_path = openmon, public;

INSERT INTO alert_triggers (tenant_id, name, asset_type, source, metric_id, expression, operator, threshold,
                            recovery_threshold, window_seconds, severity)
SELECT NULL, v.name, 'vm', 'metric', 62, 'last', '>=', v.threshold, v.recovery, 300, v.severity
  FROM (VALUES ('Volume de disco da VM acima de 90%', 90::double precision, 85::double precision, 'average'),
               ('Volume de disco da VM acima de 97%', 97::double precision, 95::double precision, 'high'))
       AS v (name, threshold, recovery, severity)
 WHERE NOT EXISTS (SELECT 1 FROM alert_triggers t WHERE t.tenant_id IS NULL AND t.name = v.name);
