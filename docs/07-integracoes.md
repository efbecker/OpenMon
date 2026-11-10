# 7. Integrações e inventário

As integrações dizem ao OpenMon **o que coletar**. Cada uma tem um tipo, um endereço, uma credencial (no cofre)
e um tenant dono. A coleta roda nos serviços `openmon-collector@<tipo>` do Servidor 1; o resultado vai para o
inventário (`assets`, `interfaces`) e para as hypertables do TimescaleDB (`metric_samples`, `interface_samples`).

| Tipo | Como coleta | Porta | Intervalo padrão |
|---|---|---|---|
| SNMP v2c/v3 | cliente SNMP próprio (base do OpenFlow) | UDP 161 | 60 s |
| VMware vCenter | API do vCenter em lote (PropertyCollector + PerfManager) | 443 | 60 s |
| Hyper-V | WinRM, uma sessão por host devolvendo JSON de todas as VMs | 5986 | 60 s |
| Veeam B&R 12+ | API REST (jobs, sessões, repositórios) | 9419 | 300 s |

## Telas

- **Integrações** (`/integracoes.html`, perfis do datacenter): lista com a última coleta, a duração e o erro, se
  houver. **Nova integração** abre o formulário do tipo escolhido; **Testar conexão** fala com o equipamento sem
  salvar nada; **Coletar agora** roda a mesma rotina do serviço e mostra o resultado.
- **Inventário** (`/inventario.html`, todos os perfis): ativos com a última leitura, filtros por tenant, tipo e
  busca. **Abrir** mostra os detalhes e as interfaces. Cliente só vê os ativos dos seus tenants (RLS no banco).
- **Backups** (`/backups.html`, todos os perfis): jobs do Veeam com a última execução, o último backup bom e o
  SLA de cada tenant; **Histórico** lista as execuções; embaixo, os repositórios com capacidade e uso.
- **Regras de tenant** (na tela Integrações, Administrador global): qual cliente é dono de cada VM ou job.

Só o Administrador global cria, edita, exclui e coleta (`integrations.manage`). Operador vê tudo, sem editar.

## SNMP

- **v2c**: informe a comunidade. Ela vai para o cofre (AES-256-GCM) e nunca volta para o navegador; ao editar,
  deixe em branco para manter.
- **v3**: usuário, autenticação (SHA-256, SHA-1 ou MD5) e criptografia (AES-128 ou DES), conforme o
  equipamento. Senhas com 8+ caracteres. Erros comuns aparecem traduzidos: usuário desconhecido, senha de
  autenticação errada (`wrongDigests`), relógio fora da janela. Com a senha de **criptografia** errada muitos
  equipamentos simplesmente não respondem: a tela avisa "sem resposta" e sugere conferir essa senha.

O que é coletado a cada intervalo (padrão 60 s):

- `system` (nome, descrição, local, uptime) e se o equipamento respondeu (métrica `up`);
- tráfego de entrada/saída (bps), erros e descartes das **interfaces monitoradas**, pelos contadores de 64 bits
  (`ifHCInOctets`/`ifHCOutOctets`; cai para 32 bits se o equipamento não tiver). A taxa é o delta entre duas
  coletas, por isso a primeira leitura de tráfego aparece na segunda coleta. Reinício do equipamento e voltas
  do contador são tratados; um delta impossível para a velocidade da porta é descartado.

As interfaces são redescobertas a cada 15 minutos (configurável em Avançado). Na primeira descoberta ficam
monitoradas as portas habilitadas (`ifAdminStatus` up) que não são loopback; o resto aparece no inventário para você marcar.

Se o equipamento não responde, a integração fica com **erro**, o ativo vira **fora** e a métrica `up` grava 0
(é nela que os alertas da etapa 4 vão se apoiar).

## VMware vCenter

Conta só de leitura: crie `openmon@vsphere.local` (ou uma conta do AD) e dê o papel **Read-only** na raiz do
vCenter, propagando para os filhos. Valide o certificado (cole a CA do vCenter em Avançado se ele usa a VMCA).

A cada coleta, um único PropertyCollector traz todo o inventário (datacenters, clusters, hosts, datastores,
VMs), paginado de 1.000 em 1.000, sem navegar objeto por objeto; o PerfManager traz, em lotes de 250 entidades
por chamada, a última amostra de 20 s de tráfego de rede, CPU ready e disco. A sessão do vCenter é reaproveitada
entre coletas (não faz login a cada minuto). No simulador oficial (vcsim) com **5.000 VMs e 40 hosts**, a coleta
inteira, gravação no banco incluída, levou ~7,5 s.

| Ativo | Métricas |
|---|---|
| VM | ligada, CPU % e MHz, vCPU, memória alocada/usada/swap/balloon, disco usado, uptime, rede rx/tx, CPU ready, IOPS |
| Host ESXi | no ar, CPU %, memória %, uptime, rede, disco; manutenção vira "manutenção" |
| Datastore | acessível, capacidade, livre, usado |

VM desligada aparece como "desligada" (não "fora"); template não entra no inventário. VM apagada no vCenter sai
do inventário na coleta seguinte, com o histórico mantido.

## Hyper-V (WinRM)

Em cada host: `winrm quickconfig -transport:https` (certificado do host) e uma conta do domínio nos grupos
**Hyper-V Administrators** e **Remote Management Users**. Em Avançado, liste os hosts (um por linha); num
cluster, liste todos os nós. Autenticação NTLM por HTTPS (5986). Por HTTP (5985) o NTLM cifra a mensagem.

Para cada host o coletor abre **uma** sessão WinRM e roda **um** script PowerShell que devolve, em JSON, o host
(CPU, memória, uptime, cluster) e todas as VMs dele (estado, vCPU, memória atribuída e demanda, uptime, IPs,
heartbeat, tráfego de rede pelos contadores "Hyper-V Virtual Network Adapter"). Até 8 hosts em paralelo.

- A VM é identificada pelo VMId: numa live migration ela muda de host no inventário sem perder o histórico.
- Host que não responde fica "fora" e a coleta termina com **aviso**; as VMs dele não são removidas do
  inventário (podem ter migrado), só quando todos os hosts responderem.

## Veeam Backup & Replication

API REST do VBR 12 ou mais novo (porta 9419). Conta `DOMINIO\usuario` com o papel **Backup Viewer** no Veeam.
A versão da API vai em Avançado: 12.0 = `1.1-rev0`, 12.1 ou mais novo = `1.1-rev1` (padrão), 13 = `1.2-rev0`.

A cada coleta: estado de todos os jobs, sessões criadas desde a última coleta (com 1 dia de folga, para pegar
backups longos) e as que ainda estavam rodando, e os repositórios com capacidade e espaço livre. Jobs que somem
do Veeam ficam no histórico marcados como removidos.

**SLA por tenant**: defina as horas no cadastro do tenant ("SLA de backup"). Um job está **em dia** quando o
último backup bom (sucesso ou aviso) terminou há menos que isso; sem SLA definido, o job aparece sem contar.
Job falhando não deixa a integração em erro: é assunto do SLA e dos alertas (etapa 4).

## Regras de tenant

O tenant da integração é o dono padrão do que ela descobre. Para distribuir VMs e jobs entre clientes, crie
regras na tela Integrações. A primeira que casa (menor prioridade primeiro) decide:

| Campo | Exemplo | Vale para |
|---|---|---|
| Pasta do vCenter | `Clientes/ACME*` (caminho) ou `ACME` (qualquer nível) | VMs do vCenter |
| Resource pool | `ACME*` | VMs do vCenter |
| Cluster | `CL-CLIENTES-*` | VMs do vCenter e do Hyper-V |
| Host Hyper-V | `hv0?.empresa.local` | VMs do Hyper-V |
| Job do Veeam | `ACME - *` | jobs do Veeam |
| Nome (regex) | `^acme-` | VMs e jobs |

Curingas `*` e `?`, sem diferenciar maiúsculas. Uma regra pode valer para todas as integrações ou só para uma.
As regras entram na coleta seguinte. Ativo com o tenant fixado à mão no Inventário não é mexido por elas.
Tags do vSphere ainda não são lidas (precisam da API REST do vCenter); use pasta ou resource pool.

## Links de clientes

Um switch do datacenter atende vários clientes. No Inventário, abra o equipamento e, na interface que atende
um cliente, marque **Link de cliente**, escolha o tenant dele e a banda contratada (Mbps). A partir daí:

- o cliente vê **só aquela porta** em "Seus links" (tráfego atual e uso da banda contratada), e não vê o
  switch nem as outras portas;
- trocar o tenant do equipamento não leva junto os links de cliente.

## Tenant dos ativos

No Inventário dá para mudar o tenant de um ativo; com **Fixar** marcado, nem a coleta nem as regras mudam mais
esse ativo.

## Serviços

```
systemctl status 'openmon-collector@*'
journalctl -u openmon-collector@snmp -f
python3 -m openmon.collector poll <id>   # coleta uma integração uma vez e mostra o resultado
```

Cada serviço reserva as integrações vencidas com um `UPDATE` condicional (dois processos nunca coletam a mesma
integração ao mesmo tempo). Paralelismo: 48 integrações SNMP, 16 Hyper-V, 4 vCenter e 4 Veeam por vez. O
instalador reinicia os coletores a cada atualização.
