-- =============================================================================
-- OpenMon - Migration 0002: integrações de coleta, ativos, interfaces, métricas
-- =============================================================================

SET search_path = openmon, public;

-- Fontes de coleta: vCenter, hosts/clusters Hyper-V, Veeam B&R/EM, SNMP.
-- Infraestrutura compartilhada pertence ao tenant provedor.
CREATE TABLE integrations (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id              bigint      NOT NULL REFERENCES tenants (id),
    kind                   text        NOT NULL CHECK (kind IN ('vmware_vcenter', 'hyperv', 'veeam', 'snmp')),
    name                   text        NOT NULL,
    endpoint               text        NOT NULL,          -- FQDN/IP ou URL base da API
    port                   integer     CHECK (port BETWEEN 1 AND 65535),
    credential_id          uuid        REFERENCES credentials (id) ON DELETE RESTRICT,
    verify_tls             boolean     NOT NULL DEFAULT true,
    ca_cert_pem            text,
    options                jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- ex.: {"winrm_transport":"kerberos"}
    poll_interval_seconds  integer     NOT NULL DEFAULT 60 CHECK (poll_interval_seconds BETWEEN 10 AND 86400),
    is_enabled             boolean     NOT NULL DEFAULT true,
    last_poll_started_at   timestamptz,
    last_poll_finished_at  timestamptz,
    last_poll_duration_ms  integer,
    last_status            text        NOT NULL DEFAULT 'never' CHECK (last_status IN ('never', 'ok', 'warning', 'error')),
    last_error             text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT integrations_name_uq UNIQUE (kind, name)
);
CREATE INDEX integrations_tenant_idx ON integrations (tenant_id);

-- Ativos monitorados (VMs, hosts, switches, storages, repositórios Veeam...)
CREATE TABLE assets (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id              bigint      NOT NULL REFERENCES tenants (id),
    integration_id         bigint      REFERENCES integrations (id) ON DELETE SET NULL,
    parent_id              bigint      REFERENCES assets (id) ON DELETE SET NULL,  -- VM -> host -> cluster
    asset_type             text        NOT NULL CHECK (asset_type IN (
                               'vcenter', 'datacenter', 'cluster', 'hypervisor_host', 'vm', 'datastore',
                               'network_switch', 'router', 'firewall', 'storage', 'physical_server',
                               'backup_server', 'backup_repository', 'other')),
    name                   text        NOT NULL,
    external_id            text,        -- MoRef do vCenter, VMId do Hyper-V, UID do Veeam, sysObjectID...
    hostname               text,
    ip_address             inet,
    vendor                 text,
    model                  text,
    serial_number          text,
    os_name                text,
    status                 text        NOT NULL DEFAULT 'unknown' CHECK (status IN (
                               'up', 'down', 'warning', 'unknown', 'maintenance', 'powered_off', 'suspended')),
    is_monitored           boolean     NOT NULL DEFAULT true,
    -- true = tenant definido manualmente; as regras automáticas não sobrescrevem
    tenant_locked          boolean     NOT NULL DEFAULT false,
    tags                   text[]      NOT NULL DEFAULT '{}',
    attributes             jsonb       NOT NULL DEFAULT '{}'::jsonb,  -- vCPU, RAM alocada, guest OS, etc.
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at           timestamptz,
    last_status_change_at  timestamptz,
    deleted_at             timestamptz,  -- some do inventário mas o histórico é mantido
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX assets_external_uq ON assets (integration_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX assets_tenant_type_idx ON assets (tenant_id, asset_type) WHERE deleted_at IS NULL;
CREATE INDEX assets_parent_idx ON assets (parent_id);
CREATE INDEX assets_ip_idx ON assets (ip_address);
CREATE INDEX assets_tags_idx ON assets USING gin (tags);

-- Atribuição automática de VMs descobertas a tenants
CREATE TABLE tenant_assignment_rules (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       bigint      NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    integration_id  bigint      REFERENCES integrations (id) ON DELETE CASCADE,  -- NULL = todas
    match_field     text        NOT NULL CHECK (match_field IN (
                        'folder', 'resource_pool', 'cluster', 'vsphere_tag', 'name_regex', 'hyperv_host', 'veeam_job')),
    pattern         text        NOT NULL,
    priority        integer     NOT NULL DEFAULT 100,
    is_enabled      boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_assignment_rules_order ON tenant_assignment_rules (priority, id) WHERE is_enabled;

-- Parâmetros SNMP por ativo (credencial v2c/v3 fica no cofre)
CREATE TABLE snmp_targets (
    asset_id         bigint   PRIMARY KEY REFERENCES assets (id) ON DELETE CASCADE,
    version          text     NOT NULL CHECK (version IN ('2c', '3')),
    port             integer  NOT NULL DEFAULT 161 CHECK (port BETWEEN 1 AND 65535),
    credential_id    uuid     NOT NULL REFERENCES credentials (id) ON DELETE RESTRICT,
    context_name     text,
    timeout_ms       integer  NOT NULL DEFAULT 2000 CHECK (timeout_ms BETWEEN 100 AND 30000),
    retries          smallint NOT NULL DEFAULT 2 CHECK (retries BETWEEN 0 AND 10),
    max_repetitions  smallint NOT NULL DEFAULT 25 CHECK (max_repetitions BETWEEN 1 AND 100),
    poll_interval_seconds integer NOT NULL DEFAULT 60 CHECK (poll_interval_seconds BETWEEN 10 AND 3600)
);

-- Interfaces / links. O tenant da interface pode diferir do tenant do
-- equipamento (porta do core switch que atende o link dedicado de um cliente).
CREATE TABLE interfaces (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id          bigint      NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    tenant_id         bigint      NOT NULL REFERENCES tenants (id),
    if_index          integer     NOT NULL CHECK (if_index > 0),
    if_name           text,
    if_alias          text,
    if_descr          text,
    if_type           integer,
    speed_bps         bigint,       -- ifHighSpeed * 1e6
    mac_address       text,
    admin_status      smallint,
    oper_status       smallint,
    is_monitored      boolean     NOT NULL DEFAULT false,
    is_customer_link  boolean     NOT NULL DEFAULT false,
    contracted_bps    bigint      CHECK (contracted_bps > 0),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT interfaces_asset_ifindex_uq UNIQUE (asset_id, if_index)
);
CREATE INDEX interfaces_tenant_idx ON interfaces (tenant_id) WHERE is_monitored;

-- Último valor bruto dos contadores 64-bit (ifHCInOctets/ifHCOutOctets) para o
-- cálculo de deltas sobreviver a reinícios do coletor. numeric(20) comporta 2^64-1.
CREATE TABLE interface_counter_state (
    interface_id    bigint        PRIMARY KEY REFERENCES interfaces (id) ON DELETE CASCADE,
    polled_at       timestamptz   NOT NULL,
    sys_uptime_cs   bigint,        -- detecta reboot do equipamento (zera contadores)
    in_octets       numeric(20,0) NOT NULL,
    out_octets      numeric(20,0) NOT NULL,
    in_ucast_pkts   numeric(20,0),
    out_ucast_pkts  numeric(20,0),
    in_errors       bigint,
    out_errors      bigint,
    in_discards     bigint,
    out_discards    bigint
);

-- Catálogo de métricas (ids fixos: smallint mantém as hypertables enxutas)
CREATE TABLE metric_definitions (
    id           smallint PRIMARY KEY,
    key          text     NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_.]{1,80}$'),
    name         text     NOT NULL,
    unit         text     NOT NULL,
    category     text     NOT NULL CHECK (category IN ('cpu', 'memory', 'disk', 'network', 'storage', 'availability', 'other')),
    value_kind   text     NOT NULL DEFAULT 'gauge' CHECK (value_kind IN ('gauge', 'rate')),
    description  text
);

INSERT INTO metric_definitions (id, key, name, unit, category, value_kind) VALUES
    (1,  'cpu.usage.pct',         'Uso de CPU',                 '%',     'cpu',          'gauge'),
    (2,  'cpu.usage.mhz',         'Uso de CPU',                 'MHz',   'cpu',          'gauge'),
    (3,  'cpu.ready.pct',         'CPU Ready',                  '%',     'cpu',          'gauge'),
    (4,  'cpu.allocated.vcpu',    'vCPUs alocadas',             'vCPU',  'cpu',          'gauge'),
    (10, 'mem.usage.pct',         'Uso de memória',             '%',     'memory',       'gauge'),
    (11, 'mem.used.bytes',        'Memória em uso',             'B',     'memory',       'gauge'),
    (12, 'mem.allocated.bytes',   'Memória alocada',            'B',     'memory',       'gauge'),
    (13, 'mem.swapped.bytes',     'Memória em swap',            'B',     'memory',       'gauge'),
    (14, 'mem.ballooned.bytes',   'Memória em ballooning',      'B',     'memory',       'gauge'),
    (20, 'disk.capacity.bytes',   'Capacidade de disco',        'B',     'disk',         'gauge'),
    (21, 'disk.used.bytes',       'Disco utilizado',            'B',     'disk',         'gauge'),
    (22, 'disk.read.latency.ms',  'Latência de leitura',        'ms',    'disk',         'gauge'),
    (23, 'disk.write.latency.ms', 'Latência de escrita',        'ms',    'disk',         'gauge'),
    (24, 'disk.read.iops',        'IOPS de leitura',            'IOPS',  'disk',         'rate'),
    (25, 'disk.write.iops',       'IOPS de escrita',            'IOPS',  'disk',         'rate'),
    (26, 'disk.read.bps',         'Throughput de leitura',      'B/s',   'disk',         'rate'),
    (27, 'disk.write.bps',        'Throughput de escrita',      'B/s',   'disk',         'rate'),
    (30, 'net.rx.bps',            'Rede recebida',              'bit/s', 'network',      'rate'),
    (31, 'net.tx.bps',            'Rede enviada',               'bit/s', 'network',      'rate'),
    (32, 'net.rx.pps',            'Pacotes recebidos',          'pkt/s', 'network',      'rate'),
    (33, 'net.tx.pps',            'Pacotes enviados',           'pkt/s', 'network',      'rate'),
    (40, 'availability.up',       'Disponibilidade',            'bool',  'availability', 'gauge'),
    (41, 'host.uptime.seconds',   'Uptime',                     's',     'availability', 'gauge'),
    (50, 'storage.capacity.bytes','Capacidade do repositório',  'B',     'storage',      'gauge'),
    (51, 'storage.free.bytes',    'Espaço livre do repositório','B',     'storage',      'gauge'),
    (52, 'storage.used.bytes',    'Espaço usado do repositório','B',     'storage',      'gauge');
