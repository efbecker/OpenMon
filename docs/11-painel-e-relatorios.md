# Painel do cliente e relatórios

Duas telas novas, para todos os perfis (permissão `reports.view`; o Cliente só vê os próprios tenants, pelo RLS):

| Tela | O que mostra |
|---|---|
| **Painel** (`/painel.html`) | Contratado x em uso agora (CPU, memória e armazenamento do VDC), gráficos do consumo em 24 h, 7, 30, 90 dias ou 12 meses com a linha do contratado, VDCs e perfis de armazenamento, VMs mais exigidas e a lista de VMs. O usuário Cliente cai direto nesta tela ao entrar. |
| **Relatórios** (`/relatorios.html`) | Cliente, tipo e período (De / Até ou atalhos). **Crescimento de recursos**: VMs, vCPU, memória e disco no fim de cada mês, variação desde o início, resumo por ano, ambiente atual, VMs criadas e removidas. **Consumo x contratado**: média, pico, percentil 95 e tempo acima de 90% de CPU, memória e armazenamento, com gráficos e VMs mais exigidas. Botões **Baixar HTML** (relatório completo num arquivo só: estilo, logo e gráficos embutidos, abre offline em qualquer navegador e pode ser enviado ao cliente), **Imprimir / PDF** (layout de papel A4, fundo branco) e **Baixar CSV** (separador `;`, decimal com vírgula). |

## De onde vêm os números

* **Contratado** = alocação do data center virtual no vCloud Director (`cpuAllocationMhz`, `memoryAllocationMB` e o limite de cada perfil de armazenamento). Limite 0 = ilimitado.
* **Em uso** = o que o vCloud informa a cada coleta (`cpuUsedMhz`, `memoryUsedMB`, `storageUsedMB`), gravado em `metric_samples`.
* **Camada da série**: até 2 dias, leituras brutas; até 90 dias, agregação horária; acima disso, diária (retenção de 62 meses).
* **Crescimento** é reconstruído pelo inventário: data de criação de cada VM (`dateCreated` da VM ou `creationDate` da vApp no vCloud; sem ela, a data em que o OpenMon viu a VM pela primeira vez) e data de remoção. Os tamanhos são os atuais de cada VM. Quando o cliente começou dentro do período, a variação é contada desde o fim do primeiro mês com VMs.

## Associar o vCloud a um cliente

Basta o VDC estar no tenant do cliente (regra automática por organização ou **Inventário > Abrir > Tenant do ativo > Fixar**). Perfis de armazenamento e VMs do VDC seguem o tenant dele na coleta seguinte; uma VM pode ser fixada à parte.

O histórico de métricas fica com o tenant que o ativo tinha no momento da leitura: o gráfico de consumo do cliente começa na primeira coleta depois da associação. O relatório de crescimento não depende disso (usa as datas de criação).

## API

| Método | Caminho | Uso |
|---|---|---|
| GET | `/api/reports/scope` | tenants consultáveis e o padrão |
| GET | `/api/reports/overview?tenant_id=` | VDCs, perfis, totais e VMs agora |
| GET | `/api/reports/consumption?tenant_id=&start=&end=` | séries e estatísticas do período |
| GET | `/api/reports/growth?tenant_id=&start=&end=` | série mensal, resumo por ano, VMs criadas e removidas |

`start`/`end` aceitam `AAAA-MM-DD` (dia inteiro) ou data/hora ISO 8601. O Cliente com um só tenant pode omitir `tenant_id`.

Gráficos: Chart.js 4.4.1 (MIT) versionado em `frontend/public/assets/vendor/`, sem CDN (a CSP só permite `'self'`).

## Relatório FinOps: dimensionamento das VMs

Em **Relatórios > FinOps: dimensionamento das VMs**: para cada VM do cliente, o alocado (vCPU, capacidade em GHz, memória,
disco), as médias de consumo no período (CPU, memória, volumes, rede, uptime), a análise e o gráfico de CPU e memória.
No topo, o resumo, as vCPU/GB liberáveis e, com os preços por vCPU, GB de RAM e GB de disco (opcionais, ficam salvos
no navegador), a economia mensal estimada. Sai em HTML, PDF e CSV como os outros.

Regras (medidas pelo percentil 95 das médias de cada ponto do período, para um pico isolado não decidir):

| Situação | Critério | Recomendação |
|---|---|---|
| CPU ociosa | P95 < 40% e mais de 1 vCPU | vCPU para ~70% de uso (com picos acima de 90%, reduz no máximo 1/4) |
| CPU sob pressão | P95 ≥ 85% (ou pico de 98% com P95 ≥ 70%) | vCPU para ~70% de uso, no mínimo +1 |
| Memória ociosa | P95 < 40% | memória para ~70% de uso, em tamanhos redondos (mínimo 4 GB no Windows, 1 GB no Linux) |
| Memória sob pressão | P95 ≥ 90% | memória para ~70% de uso |
| Volume quase cheio | volume mais cheio ≥ 90% | ampliar ou limpar |
| Disco superprovisionado | disco > 50 GB com menos de 30% usado | disco para ~70% de uso (exige migrar os dados) |
| VM ociosa | CPU média < 2%, pico < 10% e rede quase parada, em 7 dias ou mais | confirmar uso; desligar ou remover |
| Desligada no período | sem leitura ligada | arquivar ou remover (libera o disco) |

A ordem é: sob pressão primeiro, depois as que mais economizam. Até 100 VMs ganham gráfico (as que pedem ação primeiro).
API: `GET /api/reports/finops?tenant_id=&start=&end=`.
