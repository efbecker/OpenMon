# 09 · Domínio & HTTPS (certificado digital)

Tela **HTTPS** (`/https.html`, só o Administrador global). Troca o certificado autoassinado do instalador pelo
certificado do domínio, sem SSH.

1. Informe o **domínio** (ex.: `openmon.empresa.com.br`). O DNS precisa apontar para o Servidor 1 e a porta 443
   precisa estar liberada.
2. Envie o **certificado** (PEM ou CRT, pode ser o fullchain), a **chave privada** (PEM/KEY sem senha) e, se o
   certificado não trouxer os intermediários, a **cadeia intermediária**.
3. **Validar e ativar HTTPS**: o OpenMon confere se a chave casa com o certificado, se o domínio está nos nomes
   cobertos (curinga `*.empresa.com.br` vale para um nível), se está dentro da validade e monta a cadeia na ordem.
   Em seguida o Apache passa a usar o certificado e todo acesso HTTP é redirecionado para `https://<domínio>`.

A tela mostra emissor, validade (com os dias restantes), nomes cobertos, tamanho da cadeia e o SHA-256.
**Aplicar novamente** regrava o certificado guardado; **Remover** volta ao autoassinado. Para renovar com a mesma
chave, envie só o certificado novo (chave em branco usa a guardada).

## Como funciona

* A API (usuário `openmon`, sem privilégios) valida e guarda no banco: o certificado nos parâmetros e a chave
  privada **cifrada no cofre** (AES-256-GCM, credencial `tls:https`). Depois grava o pedido em
  `/var/lib/openmon/tls-requests/` (0700).
* O `openmon-tls` (root, disparado pelo `openmon-tls.path`) valida tudo de novo, grava
  `/etc/ssl/certs/openmon-domain.crt` e `/etc/ssl/private/openmon-domain.key` (0640 root:ssl-cert), liga
  `conf-enabled/openmon-domain.conf` e roda `apache2ctl configtest`. Se a configuração for recusada, volta
  exatamente ao que estava; se passar, recarrega o Apache. O resultado vai para `/var/lib/openmon/tls/status.json`.
* O autoassinado do instalador (`/etc/ssl/certs/openmon.crt`) nunca é tocado.
* **Reinstalação**: numa VM 1 nova apontando para o mesmo banco, a API percebe na subida que o certificado do banco
  não está no Apache e pede para aplicar sozinho.
* Diagnóstico: `sudo journalctl -u openmon-tls`. Toda troca fica na auditoria (`tls.upload`, `tls.reapply`,
  `tls.remove`).
