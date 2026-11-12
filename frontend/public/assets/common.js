// OpenMon - utilidades das telas logadas. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

window.OpenMon = (function () {
  const ROLE = { global_admin: "Administrador global", operator: "Operador", client: "Cliente" };
  let csrf = "";

  const $ = (id) => document.getElementById(id);

  function el(tag, opts, ...children) {
    const e = document.createElement(tag);
    if (opts) {
      if (opts.cls) e.className = opts.cls;
      if (opts.text !== undefined && opts.text !== null) e.textContent = String(opts.text);
      if (opts.title) e.title = opts.title;
      if (opts.attrs) Object.entries(opts.attrs).forEach(([k, v]) => e.setAttribute(k, v));
    }
    children.forEach((c) => c !== null && c !== undefined && c !== false && e.append(c));
    return e;
  }

  function when(iso, empty) {
    if (!iso) return empty || "—";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString("pt-BR");
  }

  async function api(method, path, body) {
    const opts = { method, cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    let res;
    try {
      res = await fetch(path, opts);
    } catch (_) {
      throw new Error("Não foi possível falar com o servidor.");
    }
    let out = null;
    try { out = await res.json(); } catch (_) { out = null; }
    if (res.status === 401) { location.replace("/login.html"); throw new Error("Sessão expirada."); }
    if (!res.ok) {
      const msg = out && (typeof out.detail === "string" ? out.detail
        : Array.isArray(out.detail) ? out.detail.map((d) => d.msg).join("; ") : "");
      if (res.status === 403 && msg === "Troque a sua senha antes de continuar.") location.replace("/senha.html");
      const err = new Error(msg || `Erro HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return out;
  }

  const CLIENT_REDIRECT = { "/home.html": "/painel.html", "/inventario.html": "/vms.html" };
  const GLOBAL_ONLY = new Set(["/integracoes.html", "/tenants.html", "/usuarios.html", "/ad.html", "/seguranca.html",
    "/https.html"]);

  // Sessão, chip do usuário, menu e botão Sair. Devolve o /me ou null (já redirecionou).
  async function boot(opts) {
    opts = opts || {};
    let me;
    try { me = await api("GET", "/api/auth/me"); } catch (_) { return null; }
    csrf = me.csrf_token;
    const u = me.user;
    if (u.must_change_password && !opts.allowPasswordChange) { location.replace("/senha.html"); return null; }
    const chip = $("user-chip");
    if (chip) chip.textContent = `${u.display_name || u.username} · ${ROLE[u.role] || u.role_name || u.role}`;
    // Telas que o cliente não usa: o Painel faz o papel do Início e a tela VMs substitui o Inventário.
    // Vale pelo caminho, não só pelo data-nav, para não depender do HTML que o navegador guardou.
    const isGlobal = u.scope === "global";
    if (!isGlobal && CLIENT_REDIRECT[location.pathname]) { location.replace(CLIENT_REDIRECT[location.pathname]); return null; }
    document.querySelectorAll("#nav a, [data-nav]").forEach((a) => {
      const need = a.getAttribute("data-nav");
      const path = (a.getAttribute("href") || "").split("?")[0];
      a.hidden = (need === "admin" && u.role !== "global_admin") || (need === "global" && !isGlobal)
        || (!isGlobal && (CLIENT_REDIRECT[path] !== undefined || GLOBAL_ONLY.has(path)));
    });
    const nav = $("nav");
    if (nav) nav.hidden = u.must_change_password;
    const out = $("btn-logout");
    if (out) out.addEventListener("click", async () => {
      try { await api("POST", "/api/auth/logout"); } catch (_) { /* segue */ }
      location.replace("/login.html");
    });
    return me;
  }

  function button(label, cls, onClick) {
    const b = el("button", { cls: `btn small-btn ${cls || "ghost"}`, text: label });
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function showError(id, message) {
    const box = $(id);
    if (!box) return;
    box.textContent = message || "";
    box.hidden = !message;
  }

  function slugify(text) {
    return String(text || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase()
      .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);
  }

  // Senha provisória forte (o administrador repassa ao usuário por um canal seguro)
  function randomPassword() {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.";
    const buf = new Uint32Array(16);
    crypto.getRandomValues(buf);
    return Array.from(buf, (n) => chars[n % chars.length]).join("");
  }

  return { ROLE, $, el, when, api, boot, button, showError, slugify, randomPassword };
})();
