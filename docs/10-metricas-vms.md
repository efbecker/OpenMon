# 10. Métricas das VMs: coleta, séries temporais e gráficos por período

Este documento descreve de onde vêm as leituras de CPU, memória, disco e rede das VMs, como ficam
guardadas e como ler as séries por período (a tela **VMs** e qualquer relatório que precise delas,
como o consumo do contrato e o crescimento do cliente).

## O que cada coletor grava por VM

Uma amostra por coleta (o intervalo da integração, 60 s por padrão), na hypertable `metric_samples`.

| Métrica (`metric_definitions.key`) | id | Unidade | vCenter | vCloud | Hyper-V |
|---|---|---|---|---|---|
| `cpu.usage.pct` | 1 | % | quickStats / maxCpuUsage | `cpu.usage.average` | `CPUUsage` |
| `cpu.usage.mhz` | 2 | MHz | quickStats | `cpu.usagemhz.average` | — |
| `cpu.ready.pct` | 3 | % | PerfManager | — | — |
| `cpu.allocated.vcpu` | 4 | vCPU | sim | sim | sim |
| `mem.usage.pct` | 10 | % | memória do guest / configurada | `mem.usage.average` | demanda / atribuída |
| `mem.used.bytes` | 11 | B | guestMemoryUsage | % x RAM configurada | `MemoryDemand` |
| `mem.allocated.bytes` | 12 | B | sim | sim | sim |
| `disk.capacity.bytes` | 20 | B | committed + uncommitted | `disk.provisioned.latest` | soma de `Get-VHD .Size` |
| `disk.used.bytes` | 21 | B | committed | `disk.used.latest` | soma de `Get-VHD .FileSize` |
| `disk.read.iops` / `disk.write.iops` | 24 / 25 | IOPS | PerfManager | — | — |
| `disk.read.bps` / `disk.write.bps` | 26 / 27 | B/s | PerfManager | `disk.read/write.average` | — |
| `net.rx.bps` / `net.tx.bps` | 30 / 31 | bit/s | PerfManager | quando o vCD expõe | contador do adaptador virtual |
| `fs.capacity.bytes` / `fs.used.bytes` | 60 / 61 | B | volumes do convidado (VMware Tools) | pelo vCenter | — |
| `fs.max.pct` | 62 | % | volume mais cheio | pelo vCenter | — |
| `availability.up` | 40 | 0/1 | ligada | ligada | ligada |

VMs desligadas gravam só a alocação (vCPU, RAM, disco) e `availability.up = 0`.

### vCloud Director

O Query Service do vCD só traz alocação. O uso real vem de
`GET /api/vApp/vm-<id>/metrics/current`, uma chamada por VM ligada, 16 em paralelo por padrão
(`options.metrics_concurrency`, até 64). Para 3.000 VMs isso leva poucos segundos. Requisitos:

* a conta da integração precisa do direito **View VM metrics** (o papel de provedor já tem). Sem ele a
  coleta continua só com o inventário e a integração fica em "aviso" com essa mensagem;
* `options.vm_metrics = false` desliga essa parte (só inventário);
* VMs sem VMware Tools ou recém-ligadas podem vir sem dado; ficam só com a alocação naquela coleta.

Disco: o provisionado vem de `disk.provisioned.latest`, ou do `totalStorageAllocatedMb` do Query Service, ou,
se nenhum dos dois vier, do hardware virtual (`/api/vApp/vm-<id>/virtualHardwareSection/disks`, soma dos discos,
relido a cada 6 h). O espaço usado só existe se o vCD mandar `disk.used.latest`; quando não manda, cadastre o
vCenter por baixo. O botão **Testar conexão** da integração mostra, para uma VM ligada, os campos de disco e
os nomes das métricas que este vCD devolve.

Rede por VM depende da versão do vCD. Se não vier, cadastre também o vCenter por baixo.

### vCenter completando o vCloud

Com o vCenter que hospeda o vCD também cadastrado, a coleta do vCenter acha cada VM do vCloud pelo MoRef e grava
nela os volumes do sistema (`attributes.volumes` = `[{path, cap, free, fs}]` e métricas 60 a 62), o disco usado
(`committed`), uptime, rede, IOPS e CPU Ready, sem criar uma VM duplicada. Isso resolve o vCD que não manda
`disk.used.latest`. Desligue com `options.vcd_merge = false` na integração do vCenter.

## Onde fica guardado (camadas)

Definido na migration 0003. Retenção ajustável em `system_settings` (`retention.*`).

| Camada | Resolução | Guarda | Leitura pela API (respeita tenant) |
|---|---|---|---|
| `metric_samples` | bruto (~60 s) | 35 dias | `v_metric_samples (time, tenant_id, asset_id, metric_id, value)` |
| `metric_hourly` | 1 hora | 25 meses | `v_metric_hourly (bucket, …, samples, avg_value, min_value, max_value)` |
| `metric_daily` | 1 dia | 62 meses | `v_metric_daily (…, avg_value, min_value, max_value, peak_hour_avg)` |

As agregações são em tempo real (`materialized_only = false`): a hora e o dia correntes já aparecem.
Para juntar baldes, reagregue com `sum(avg_value * samples) / sum(samples)`, nunca média de médias.

**Tenant da amostra.** Cada amostra guarda o `tenant_id` do ativo no momento da coleta, e as views
`v_metric_*` só devolvem as amostras de tenants visíveis à sessão. Se uma VM muda de cliente (regra
nova ou tenant fixado no inventário), o cliente novo vê a VM a partir da mudança; o histórico anterior
continua com o tenant antigo. O administrador global vê tudo.

## API

### Lista de VMs com a última leitura

`GET /api/assets?asset_type=vm&limit=5000[&tenant_id=&q=]` (permissão `assets.view`). Cada item traz
`latest` com `cpu_pct`, `mem_pct`, `mem_used`, `disk_capacity`, `disk_used`, `disk_read_bps`,
`disk_write_bps`, `net_rx_bps`, `net_tx_bps`, `up`, `uptime_s` (leituras dos últimos 30 min) e
`attributes` com `vcpu`, `memory_bytes`, `hypervisor` (`vmware`, `vcloud`, `hyperv`), `org`, `vdc`,
`cluster`, `host`.

### Séries de um ativo por período

`GET /api/assets/{id}/metrics` (permissão `assets.view`; funciona para VM, host, datastore, VDC…)

| Parâmetro | Exemplo | |
|---|---|---|
| `period` | `1h`, `6h`, `24h`, `7d`, `30d`, `90d`, `180d`, `365d`, `730d`, `1825d` | padrão `24h` |
| `from`, `to` | `2026-10-01T00:00:00Z` | ISO 8601; substitui `period`; máximo 5 anos |
| `keys` | `cpu.usage.pct,disk.used.bytes` | filtra métricas; sem ele vêm todas as que têm dado |

A camada é escolhida pelo tamanho e pela idade do período, com no máximo ~480 pontos por série:

| Período | Camada | Um ponto a cada |
|---|---|---|
| até 2 dias (e começando nos últimos 34 dias) | bruto | 1, 5, 15, 30 min ou 1 h |
| até 90 dias (e nos últimos ~25 meses) | horária | 1, 3, 6, 12 h ou 1 dia |
| acima | diária | 1 dia, 7 dias ou 30 dias |

Resposta:

```json
{
  "asset": {"id": 42, "name": "POLLUX-APP01", "asset_type": "vm", "status": "up", "tenant_id": 3,
            "tenant_name": "CLIENTE_POLLUX", "vcpu": 2, "memory_bytes": 4294967296},
  "from": "2026-11-10T13:00:00+00:00", "to": "2026-11-11T13:00:00+00:00",
  "tier": "raw", "bucket_seconds": 300,
  "series": [
    {"key": "cpu.usage.pct", "name": "Uso de CPU", "unit": "%", "category": "cpu", "kind": "gauge",
     "points": [[1762779600000, 21.4, 12.0, 35.2], "…"],
     "stats": {"avg": 32.4, "min": 3.1, "max": 59.7, "first": 21.4, "last": 25.0}}
  ]
}
```

`points` é `[epoch em ms, média, mínimo, máximo]` do balde. `stats.avg` é a média dos baldes;
`first`/`last` são a média do primeiro e do último balde (crescimento de disco no período =
`last - first` de `disk.used.bytes`).

Ativo de outro tenant responde 404, igual a um ativo inexistente.

## O que o cliente não vê

Para sessões que não são do administrador global, a API tira dos ativos o host ESXi, cluster, resource pool,
pasta, MoRef, provider VDC, nome do vCenter, `external_id` e a integração de origem. Nas VMs do vCloud o
`hostname` também sai (o vCD manda ali o host ESXi; o nome vai para `attributes.esx_host`, que só o admin vê).

## Tela VMs (`/vms.html`)

* Painel da frota, um por cliente (o cliente vê só o seu ambiente; o admin filtra por tenant): indicadores de
  servidores ligados, problemas ativos, média de CPU e memória, volume mais cheio e tráfego; cards por VM com
  CPU, memória e disco coloridos pela saúde (atenção 85/90/90 %, crítico 95/97/97 %); maior consumo; problemas
  ativos; discos com menos espaço (limites 90 e 97 %); sistemas operacionais e uptime. Atualiza a cada minuto.
* Visualização em tabela com ordenação por coluna, filtro por situação (inclusive "em atenção") e busca.
* O detalhe da VM mostra os volumes do sistema e os gráficos.
* Cada card mostra o tipo de sistema (Windows, Linux, outro) e o nome curto; há filtro por sistema.
* Alertas de disco ligados de fábrica (migration 0007, para todos os tenants): volume mais cheio ≥ 90 %
  (média) e ≥ 97 % (alta), os mesmos limites que pintam a VM de atenção e crítico. Assim o status da VM e os
  Problemas ativos vêm da mesma regra. Sem VMware Tools só há o disco no datastore (usado/provisionado, com
  snapshots, pode passar de 100 %): ele aparece como DATASTORE no card, sem cor e fora da saúde e dos alertas.
* O Início saiu do menu: todos entram no Painel.
* Para o cliente, a tela VMs substitui o Inventário e os Alertas (o menu Inventário só aparece para o provedor) e o Painel
  mostra só o contratado x em uso e o consumo no período.
* **Gráficos**: períodos de 1 hora a 1 ano ou datas escolhidas; CPU e memória (média e pico), disco
  usado x provisionado, volume mais cheio, espaço nos volumes, leitura/escrita em disco, IOPS, rede recebida/enviada, CPU Ready. O endereço
  guarda a VM e o período (`/vms.html?id=42&period=7d`) para compartilhar o link.
* No Inventário, VMs, hosts, VDCs e datastores têm o botão **Gráficos**, que abre a mesma tela.
* Gráficos com Chart.js 4.4.1 (MIT) versionado em `frontend/public/assets/vendor/`, sem CDN (CSP
  `script-src 'self'`).
