// OpenMon - tela Branding (logo, favicon e banner da tela de login). Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const SLOTS = [
    { kind: "logo", title: "Logo", accept: ".png,.svg,.jpg,.jpeg,image/png,image/svg+xml,image/jpeg",
      help: "Cabeçalho das telas, login e relatórios. Prefira fundo transparente e formato horizontal." },
    { kind: "favicon", title: "Favicon", accept: ".ico,.png,image/x-icon,image/vnd.microsoft.icon,image/png",
      help: "Ícone da aba do navegador. Quadrado, 32×32 ou 64×64." },
    { kind: "banner", title: "Banner de login", accept: ".png,.svg,.webp,.jpg,.jpeg,image/png,image/svg+xml,image/webp,image/jpeg",
      help: "Imagem ao lado do formulário na tela de login. Algo como 1200×900." },
  ];
  let csrf = "";
  let data = null;

  function size(n) {
    if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} MB`;
    return `${Math.max(1, Math.round(n / 1024))} KB`;
  }

  function flash(msg) {
    $("flash").textContent = msg || "";
    $("flash").hidden = !msg;
  }

  async function send(slot, file, btn, errId) {
    showError(errId, "");
    flash("");
    const lim = data.limits[slot.kind];
    if (!file) { showError(errId, "Escolha um arquivo primeiro."); return; }
    if (file.size > lim.max_bytes) { showError(errId, `Arquivo de ${size(file.size)}: o limite é ${lim.hint}.`); return; }
    btn.disabled = true;
    try {
      let res;
      try {
        res = await fetch(`/api/admin/branding/${slot.kind}`, {
          method: "PUT", cache: "no-store", credentials: "same-origin", body: file,
          headers: { Accept: "application/json", "Content-Type": file.type || "application/octet-stream",
            "X-CSRF-Token": csrf, "X-Filename": encodeURIComponent(file.name).slice(0, 200) },
        });
      } catch (_) {
        throw new Error("Não foi possível falar com o servidor.");
      }
      let out = null;
      try { out = await res.json(); } catch (_) { out = null; }
      if (res.status === 401) { location.replace("/login.html"); return; }
      if (!res.ok) {
        const msg = out && typeof out.detail === "string" ? out.detail
          : res.status === 413 ? `Arquivo maior que o permitido (${lim.hint}).` : `Erro HTTP ${res.status}`;
        throw new Error(msg);
      }
      flash(`${slot.title} atualizado.`);
      await load();
    } catch (e) {
      showError(errId, e.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function remove(slot, btn, errId) {
    if (!confirm(`Remover ${slot.title.toLowerCase()} e voltar ao padrão do OpenMon?`)) return;
    showError(errId, "");
    flash("");
    btn.disabled = true;
    try {
      await api("DELETE", `/api/admin/branding/${slot.kind}`);
      flash(`${slot.title} removido.`);
      await load();
    } catch (e) {
      showError(errId, e.message);
    } finally {
      btn.disabled = false;
    }
  }

  function preview(slot, item) {
    const box = el("div", { cls: `brand-preview brand-preview-${slot.kind}` });
    if (item) box.append(el("img", { attrs: { src: item.url, alt: slot.title } }));
    else box.append(el("span", { cls: "muted small", text: "nenhum (padrão do OpenMon)" }));
    return box;
  }

  function slotCard(slot) {
    const item = data.items[slot.kind];
    const lim = data.limits[slot.kind];
    const errId = `err-${slot.kind}`;
    const input = el("input", { attrs: { type: "file", accept: slot.accept, id: `file-${slot.kind}` } });
    const pick = el("div", { cls: "brand-pick" });
    const sendBtn = button(`Enviar ${slot.title.toLowerCase()}`, "deploy", () => send(slot, input.files[0], sendBtn, errId));
    pick.append(input, sendBtn);
    if (item) {
      const rm = button("Remover", "ghost", () => remove(slot, rm, errId));
      pick.append(rm);
    }
    input.addEventListener("change", () => {
      showError(errId, "");
      const f = input.files[0];
      if (f && f.size > lim.max_bytes) showError(errId, `Arquivo de ${size(f.size)}: o limite é ${lim.hint}.`);
    });
    const meta = item
      ? el("div", { cls: "muted tiny", text: `${item.filename ? item.filename + " · " : ""}${size(item.size)} · enviado por ${item.uploaded_by || "—"} em ${when(item.uploaded_at)}` })
      : null;
    return el("div", { cls: "brand-slot" },
      el("div", { cls: "brand-slot-head" }, el("strong", { text: slot.title }), el("span", { cls: "muted small", text: lim.hint })),
      preview(slot, item), meta,
      el("label", { cls: "field" }, el("span", { cls: "muted small", text: slot.help }), pick),
      el("p", { cls: "error-text", attrs: { id: errId }, }));
  }

  function render() {
    const box = $("slots");
    box.replaceChildren(...SLOTS.map(slotCard));
    box.querySelectorAll(".error-text").forEach((p) => { p.hidden = true; });
  }

  async function load() {
    showError("state-error", "");
    try {
      data = await api("GET", "/api/admin/branding");
      render();
      if (window.OpenMonBranding) window.OpenMonBranding.refresh();
    } catch (e) {
      showError("state-error", e.message);
    }
  }

  async function start() {
    const me = await boot();
    if (!me) return;
    csrf = me.csrf_token;
    if (me.user.role !== "global_admin") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    await load();
  }

  start();
})();
