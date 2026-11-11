// OpenMon - Domínio & HTTPS (certificado digital do Apache). Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  let data = null;
  let waiting = null;   // id do pedido aguardando o openmon-tls

  function day(iso) {
    return iso ? new Date(iso).toLocaleDateString("pt-BR") : "—";
  }

  function flash(msg) {
    $("flash").textContent = msg;
    $("flash").hidden = !msg;
  }

  function line(label, value, cls) {
    return el("div", { cls: "kv" }, el("span", { cls: "muted", text: label + " " }), el("span", { cls: cls || "", text: value }));
  }

  function certInfo(info) {
    const left = info.days_left;
    return [
      el("div", { cls: "kv-grid" },
        line("Emitido por:", info.issuer),
        el("div", { cls: "kv" }, el("span", { cls: "muted", text: "Validade: " }),
          el("span", { text: `${day(info.not_before)} a ${day(info.not_after)} ` }),
          el("span", { cls: left < 15 ? "bad small" : left < 30 ? "warn small" : "muted small", text: `(${left} dias restantes)` })),
        line("Nomes cobertos:", info.names.join(", "), "mono"),
        line("Cadeia:", `${info.chain_count || 1} certificado(s)`)),
      el("div", { cls: "mono tiny muted mt-s", text: "SHA-256 " + info.sha256 }),
    ];
  }

  function render() {
    const box = $("current");
    const st = data.status;
    const stored = data.stored;
    const parts = [];
    if (!st) {
      parts.push(el("p", { cls: "muted", text: "O serviço openmon-tls ainda não publicou o estado do Apache. Rode o instalador de novo no Servidor 1 (curl) para ativá-lo." }));
    } else if (st.mode === "custom") {
      parts.push(el("div", { cls: "cert-head" }, el("span", { cls: "mono strong-line", text: `https://${st.domain}` }),
        el("span", { cls: "tag tag-ok", text: "HTTPS ativo" })));
      if (st.info) parts.push(...certInfo(st.info));
    } else {
      parts.push(el("div", { cls: "cert-head" }, el("span", { cls: "strong-line", text: "Certificado autoassinado do instalador" }),
        el("span", { cls: "tag tag-auto", text: "autoassinado" })));
      parts.push(el("p", { cls: "muted small", text: "Os navegadores mostram aviso de segurança. Envie o certificado do domínio abaixo." }));
      if (st.info) parts.push(line("Nomes:", st.info.names.join(", "), "mono"), line("Validade até:", day(st.info.not_after)));
    }
    if (stored) {
      parts.push(el("div", { cls: "muted small mt-s", text: `Guardado no banco: ${stored.domain} · enviado por ${stored.uploaded_by || "—"} em ${when(stored.uploaded_at)}` }));
    }
    const last = st && st.last;
    if (last && last.ok === false) parts.push(el("p", { cls: "error-text", text: `Última tentativa (${when(last.at)}): ${last.message}` }));
    if (data.pending || waiting) parts.push(el("p", { cls: "muted small", text: "Aplicando no Apache…" }));
    const acts = el("div", { cls: "row mt" });
    if (stored) {
      acts.append(button("Aplicar novamente", "ghost", () => act("POST", "/api/admin/tls/reapply", null)));
      acts.append(button("Remover e voltar ao autoassinado", "ghost", () => {
        if (!confirm("Remover o certificado do domínio? O Apache volta ao certificado autoassinado e os navegadores passam a mostrar aviso.")) return;
        act("DELETE", "/api/admin/tls", "Certificado removido.");
      }));
    }
    if (acts.childElementCount) parts.push(acts);
    box.replaceChildren(...parts);
    $("form-title").textContent = stored ? "Trocar certificado" : "Enviar certificado";
    if (stored && !$("f-domain").value) $("f-domain").value = stored.domain;
    $("key-hint").textContent = stored ? "PEM/KEY sem senha. Em branco, usa a chave guardada (renovação com a mesma chave)." : "PEM/KEY sem senha.";
  }

  async function load() {
    try {
      data = await api("GET", "/api/admin/tls");
      showError("state-error", "");
      const last = data.status && data.status.last;
      if (waiting && last && last.id === waiting) {
        if (last.ok) flash(last.message.charAt(0).toUpperCase() + last.message.slice(1) + ".");
        waiting = null;
      }
      render();
      if (waiting || data.pending) setTimeout(load, 2000);
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
      showError("state-error", e.message);
    }
  }

  async function act(method, url, msg) {
    flash("");
    showError("state-error", "");
    try {
      const r = await api(method, url);
      waiting = r.request_id;
      if (msg) flash(msg);
      await load();
    } catch (e) {
      showError("state-error", e.message);
    }
  }

  // Lê o arquivo como texto; .crt/.cer em DER (binário) vira PEM aqui mesmo
  function readFile(input, kind) {
    const f = input.files && input.files[0];
    if (!f) return Promise.resolve("");
    if (f.size > 200000) return Promise.reject(new Error(`${f.name}: arquivo grande demais.`));
    return f.arrayBuffer().then((buf) => {
      const bytes = new Uint8Array(buf);
      const text = new TextDecoder().decode(bytes);
      if (text.includes("-----BEGIN") || kind === "key") return text;
      let bin = "";
      bytes.forEach((b) => { bin += String.fromCharCode(b); });
      const b64 = btoa(bin).replace(/.{1,64}/g, "$&\n");
      return `-----BEGIN CERTIFICATE-----\n${b64}-----END CERTIFICATE-----\n`;
    });
  }

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    flash("");
    const domain = $("f-domain").value.trim();
    if (!domain) return showError("form-error", "Informe o domínio.");
    if (!$("f-cert").files.length) return showError("form-error", "Escolha o arquivo do certificado.");
    if (!$("f-key").files.length && !(data && data.stored)) return showError("form-error", "Escolha o arquivo da chave privada.");
    $("btn-save").disabled = true;
    try {
      const [certificate, privateKey, chain] = await Promise.all([readFile($("f-cert"), "cert"),
        readFile($("f-key"), "key"), readFile($("f-chain"), "cert")]);
      const r = await api("POST", "/api/admin/tls", { domain, certificate, private_key: privateKey || null, chain: chain || null });
      waiting = r.request_id;
      flash(`Certificado válido (${r.info.issuer}, até ${day(r.info.not_after)}). Ativando no Apache…` + (r.warning ? " Atenção: " + r.warning : ""));
      ["f-cert", "f-key", "f-chain"].forEach((id) => { $(id).value = ""; });
      await load();
    } catch (e) {
      showError("form-error", e.message);
    } finally {
      $("btn-save").disabled = false;
    }
  });

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.role !== "global_admin") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  })();
})();
