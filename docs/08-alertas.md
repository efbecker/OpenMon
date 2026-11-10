# 08 · Alertas e notificações

Os alertas são avaliados pelo serviço `openmon-scheduler` (VM 1). A cada 30 s ele:

1. pega um *advisory lock* no PostgreSQL (`pg_try_advisory_xact_lock`), para que só uma instância avalie por vez;
2. avalia cada alerta ativo e abre ou fecha problemas;
3. envia as notificações pendentes (e-mail, Telegram, webhook), com nova tentativa em caso de falha.

Para rodar uma vez só (diagnóstico): `sudo -u openmon /opt/openmon/venv/bin/python -m openmon.scheduler once`.

## Telas

- **Alertas** (`/alertas.html`): problemas em aberto ou resolvidos, contagem por severidade e botão
  **Reconhecer** com comentário. O reconhecimento é registrado na auditoria, e os canais do alerta recebem um aviso
  de que alguém está cuidando do problema. Cliente vê só os problemas do próprio tenant (RLS).
- **Configurar alertas** (`/alertas-config.html`, perfis com `alerts.manage`): alertas, canais, teste de envio e
  últimos 50 envios.

## Tipos de alerta

| Fonte | Condição |
|---|---|
| Métrica | `média`, `última`, `mínima` ou `máxima` da métrica na janela, comparada ao limite. O armazenamento usado é comparado em % da capacidade. |
| Uso de interface | % da banda da interface na janela (entrada ou saída, o maior). |
| Fora do ar | ativo sem coleta com sucesso há mais tempo que a janela. |
| Backup | job com última execução com falha, ou sem sucesso dentro do SLA do tenant (limite 0) ou de N horas. |
| Integração | integração com erro na última coleta (um problema só para todas). |

Cada alerta pode valer para todos os ativos, para um tipo (Host, VM, Switch…) ou para um ativo específico, e para um tenant
ou para todos. A **recuperação** opcional evita que o problema fique abrindo e fechando: com limite > 90 e recuperação 80,
o problema só fecha abaixo de 80. Ao desativar ou excluir um alerta, os problemas dele são fechados.

**Adicionar recomendados** cria 7 alertas prontos (fora do ar, CPU, memória, datastore, link, backup e integração), sem
duplicar os que já existem com o mesmo nome.

## Canais

| Canal | Segurança |
|---|---|
| E-mail (SMTP) | só STARTTLS (porta 587) ou TLS direto (465), com verificação do certificado. Sem TLS não é aceito. |
| Telegram | token do bot e chat ID. O token nunca aparece em logs nem em mensagens de erro. |
| Webhook | só `https://`. Corpo JSON assinado: `X-OpenMon-Signature: sha256=<HMAC-SHA256(segredo, timestamp + "." + corpo)>` e `X-OpenMon-Timestamp`. Rejeite no receptor timestamps com mais de 5 min. |

Senhas, tokens e segredos ficam no cofre (AES-256-GCM, chave em `/etc/openmon/master.key`). Um canal de um tenant
só recebe os problemas dos ativos daquele tenant. Falhas de envio são tentadas de novo até 5 vezes no total (1, 4, 9 e 16 min depois da primeira).

Exemplo de verificação do webhook em Python:

```python
import hashlib, hmac, time
def valido(segredo: bytes, ts: str, corpo: bytes, assinatura: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    esperado = "sha256=" + hmac.new(segredo, ts.encode() + b"." + corpo, hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperado, assinatura)
```

## Limpeza

O agendador também apaga sessões expiradas e envios com mais de 180 dias.
