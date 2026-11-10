# 7. Integrações e inventário

As integrações dizem ao OpenMon **o que coletar**. Cada uma tem um tipo, um endereço, uma credencial (no cofre)
e um tenant dono. A coleta roda nos serviços `openmon-collector@<tipo>` do Servidor 1; o resultado vai para o
inventário (`assets`, `interfaces`) e para as hypertables do TimescaleDB (`metric_samples`, `interface_samples`).

| Tipo | Como coleta | Situação |
|---|---|---|
| SNMP v2c/v3 | UDP 161, cliente SNMP próprio (base do OpenFlow) | ✅ disponível |
| VMware vCenter | API do vCenter em lote (PropertyCollector + PerfManager) | próxima entrega |
| Hyper-V | WinRM, uma sessão por host devolvendo JSON de todas as VMs | próxima entrega |
| Veeam B&R | API REST (jobs, sessões, repositórios, SLA por tenant) | próxima entrega |

## Telas

- **Integrações** (`/integracoes.html`, perfis do datacenter): lista com a última coleta, a duração e o erro, se
  houver. **Nova integração** abre o formulário do tipo escolhido; **Testar conexão** fala com o equipamento sem
  salvar nada; **Coletar agora** roda a mesma rotina do serviço e mostra o resultado.
- **Inventário** (`/inventario.html`, todos os perfis): ativos com a última leitura, filtros por tenant, tipo e
  busca. **Abrir** mostra os detalhes e as interfaces. Cliente só vê os ativos dos seus tenants (RLS no banco).

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

## Links de clientes

Um switch do datacenter atende vários clientes. No Inventário, abra o equipamento e, na interface que atende
um cliente, marque **Link de cliente**, escolha o tenant dele e a banda contratada (Mbps). A partir daí:

- o cliente vê **só aquela porta** em "Seus links" (tráfego atual e uso da banda contratada), e não vê o
  switch nem as outras portas;
- trocar o tenant do equipamento não leva junto os links de cliente.

## Tenant dos ativos

O tenant da integração é o dono padrão do que ela descobre. No Inventário dá para mudar o tenant de um ativo;
com **Fixar** marcado, nem a coleta nem as regras automáticas mudam mais esse ativo.

## Serviços

```
systemctl status 'openmon-collector@*'
journalctl -u openmon-collector@snmp -f
python3 -m openmon.collector poll <id>   # coleta uma integração uma vez e mostra o resultado
```

Cada serviço reserva as integrações vencidas com um `UPDATE` condicional (dois processos nunca coletam a mesma
integração ao mesmo tempo) e roda até 48 coletas SNMP em paralelo. O instalador reinicia os coletores a cada
atualização.
