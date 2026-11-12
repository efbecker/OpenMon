-- =============================================================================
-- OpenMon - Migration 0006: espaço em disco do sistema convidado (VMware Tools)
--
-- Somas dos volumes (C:, F:, /, /var...) de cada VM e o volume mais cheio. O detalhe
-- por volume fica em assets.attributes.volumes (última leitura).
-- =============================================================================

SET search_path = openmon, public;

INSERT INTO metric_definitions (id, key, name, unit, category, value_kind, description) VALUES
    (60, 'fs.capacity.bytes', 'Volumes do sistema: tamanho', 'B', 'disk', 'gauge',
     'Soma do tamanho dos volumes vistos pelo sistema operacional da VM'),
    (61, 'fs.used.bytes',     'Volumes do sistema: em uso',  'B', 'disk', 'gauge',
     'Soma do espaço usado nos volumes vistos pelo sistema operacional da VM'),
    (62, 'fs.max.pct',        'Volume mais cheio',          '%', 'disk', 'gauge',
     'Ocupação do volume mais cheio da VM')
ON CONFLICT (id) DO NOTHING;
