// OpenMon - tela Segurança (Fail2ban). Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  let csrf = "";
  let data = null;
  let timer = null;
  const ROLE = { global_admin: "Administrador global", operator: "Operador", client: "Cliente" };

  function el(tag, opts, ...children) {
    const e = document.createElement(tag);
    if (opts) {
      if (opts.cls) e.className = opts.cls;
      if (opts.text !== undefined) e.textContent = String(opts.text);
      if (opts.title) e.title = opts.title;
    }
    children.forEach((c) => c && e.append(c));
    return e;
  }

  function when(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString("pt-BR");
  }

  async function api(method, path, body) {
    const opts = { method, cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
    if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    let out = null;
    try { out = await res.json(); } catch (_) { out = null; }
    if (res.status === 401) { location.replace("/login.html"); throw new Error("sessão expirada"); }
    if (!res.ok) {
      const msg = out && (typeof out.detail === "string" ? out.detail
        : Array.isArray(out.detail) ? out.detail.map((d) => d.msg).join("; ") : "");
      const err = new Error(msg || `Erro HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return out;
  }

  function stat(k, v, cls) {
    return el("div", { cls: "stat" }, el("div", { cls: "k", text: k }), el("div", { cls: "v " + (cls || ""), text: v }));
  }

  function actionBtn(label, cls, onClick) {
    const b = el("button", { cls: `btn small-btn ${cls}`, text: label });
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  function render() {
    const d = data;
    const auto = (d.jails && d.jails["openmon-auth"]) || {};
    $("stats").replaceChildren(
      stat("Fail2ban", d.fail2ban_running ? "ativo" : "parado", d.fail2ban_running ? "good" : "bad"),
      stat("Bloqueados agora", String(d.bans.length)),
      stat("Bloqueios automáticos (total)", String(auto.total_banned ?? "—")),
      stat("Falhas de login em análise", String(auto.currently_failed ?? "—")),
      stat("Seu IP", d.your_ip || "—"),
      stat("Atualizado em", when(d.updated_at)),
    );
    const note = $("bridge-note");
    if (!d.bridge_ok) {
      note.textContent = d.updated_at
        ? "O estado do Fail2ban não é atualizado há alguns minutos. No Servidor 1: sudo systemctl status openmon-fail2ban.timer"
        : "Ainda não há estado do Fail2ban. No Servidor 1: sudo systemctl start openmon-fail2ban (ou rode o instalador de novo).";
      note.hidden = false;
    } else if (d.pending.length) {
      note.textContent = `Aplicando ${d.pending.length} pedido(s) no Fail2ban…`;
      note.hidden = false;
    } else {
      note.hidden = true;
    }

    // Bloqueados
    const pendingUnban = new Set(d.pending.filter((p) => p.action === "unban").map((p) => p.ip));
    const bansBody = $("bans-table").tBodies[0];
    bansBody.replaceChildren(...d.bans.map((b) => {
      const manual = b.jail === "openmon-manual";
      const origin = el("span", { cls: "tag " + (manual ? "tag-manual" : "tag-auto"),
        text: manual ? "Manual" : "Automático (falhas de login)" });
      const reason = manual ? [b.reason, b.by ? `por ${b.by}` : ""].filter(Boolean).join(" · ") : "excesso de falhas de login";
      const cell = el("td");
      if (pendingUnban.has(b.ip)) cell.append(el("span", { cls: "muted small", text: "desbloqueando…" }));
      else cell.append(actionBtn("Desbloquear", "ghost", () => doAction("unban", b.ip)));
      return el("tr", null, el("td", { cls: "mono", text: b.ip }), el("td", null, origin), el("td", { text: when(b.banned_at) }),
        el("td", { text: b.permanent ? "até desbloquear" : when(b.expires_at) }), el("td", { text: reason || "—" }), cell);
    }));
    $("bans-count").textContent = d.bans.length ? `(${d.bans.length})` : "";
    $("bans-empty").hidden = d.bans.length > 0;

    // IPs
    $("window-h").textContent = d.window_hours;
    const q = $("ip-filter").value.trim().toLowerCase();
    const rows = d.ips.filter((r) => !q || r.ip.toLowerCase().includes(q) || (r.usernames || []).some((u) => u.toLowerCase().includes(q)));
    const pendingBan = new Set(d.pending.filter((p) => p.action === "ban").map((p) => p.ip));
    $("ips-table").tBodies[0].replaceChildren(...rows.map((r) => {
      const ipCell = el("td", { cls: "mono", text: r.ip });
      if (r.ip === d.your_ip) ipCell.append(" ", el("span", { cls: "tag tag-you", text: "você" }));
      if (r.banned_in.length) ipCell.append(" ", el("span", { cls: "tag tag-bad", text: "bloqueado" }));
      const act = el("td");
      if (pendingBan.has(r.ip)) act.append(el("span", { cls: "muted small", text: "bloqueando…" }));
      else if (r.banned_in.length) act.append(actionBtn("Desbloquear", "ghost", () => doAction("unban", r.ip)));
      else if (r.ip !== d.your_ip) act.append(actionBtn("Bloquear", "danger", () => doAction("ban", r.ip)));
      const logins = el("td", { text: `${r.successes} / ` });
      logins.append(el("span", { cls: r.failures ? "bad" : "", text: String(r.failures) }));
      return el("tr", { cls: r.failures >= 5 ? "row-warn" : "" }, ipCell, el("td", { text: r.requests }),
        el("td", { text: r.errors_4xx }), logins, el("td", { text: (r.usernames || []).join(", ") || "—" }),
        el("td", { text: when(r.last_seen) }), el("td", { cls: "mono small", text: r.last_request || "—", title: r.user_agent || "" }), act);
    }));
    $("ips-count").textContent = d.ips.length ? `(${d.ips.length})` : "";
    $("ips-empty").hidden = rows.length > 0;

    // Histórico
    const LABEL = { ban: "Bloquear", unban: "Desbloquear" };
    $("hist-table").tBodies[0].replaceChildren(...d.history.map((h) => el("tr", null,
      el("td", { text: when(h.at) }), el("td", { text: LABEL[h.action] || h.action }), el("td", { cls: "mono", text: h.ip || "—" }),
      el("td", { text: h.by || "—" }), el("td", { cls: h.ok ? "good" : "bad", text: h.ok ? "aplicado" : (h.error || "falhou") }))));
    $("hist-empty").hidden = d.history.length > 0;
  }

  async function load() {
    clearTimeout(timer);
    try {
      data = await api("GET", "/api/admin/security/overview");
      render();
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
    }
    timer = setTimeout(load, data && data.pending.length ? 2000 : 15000);
  }

  async function doAction(action, ip, reason) {
    $("ban-error").hidden = true;
    $("ban-ok").hidden = true;
    if (action === "unban" && !confirm(`Desbloquear ${ip}?`)) return;
    if (action === "ban" && reason === undefined && !confirm(`Bloquear ${ip} nas portas 80/443?`)) return;
    try {
      await api("POST", `/api/admin/security/${action}`, { ip, reason: reason || null });
      $("ban-ok").textContent = action === "ban" ? `Pedido enviado: bloquear ${ip}.` : `Pedido enviado: desbloquear ${ip}.`;
      $("ban-ok").hidden = false;
    } catch (e) {
      $("ban-error").textContent = e.message;
      $("ban-error").hidden = false;
    }
    load();
  }

  $("ban-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const ip = $("ban-ip").value.trim();
    if (!ip) return;
    doAction("ban", ip, $("ban-reason").value.trim()).then(() => {
      if ($("ban-error").hidden) { $("ban-ip").value = ""; $("ban-reason").value = ""; }
    });
  });
  $("ip-filter").addEventListener("input", () => data && render());
  $("btn-refresh").addEventListener("click", load);

  $("btn-logout").addEventListener("click", async () => {
    try { await api("POST", "/api/auth/logout"); } catch (_) { /* segue */ }
    location.replace("/login.html");
  });

  async function boot() {
    let me;
    try { me = await api("GET", "/api/auth/me"); } catch (_) { return; }
    csrf = me.csrf_token;
    const u = me.user;
    if (u.must_change_password) { location.replace("/senha.html"); return; }
    $("user-chip").textContent = `${u.display_name || u.username} · ${ROLE[u.role] || u.role}`;
    document.querySelectorAll("[data-nav]").forEach((a) => {
      const need = a.getAttribute("data-nav");
      a.hidden = (need === "admin" && u.role !== "global_admin") || (need === "global" && u.scope !== "global");
    });
    $("nav").hidden = false;
    if (u.role !== "global_admin") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  }

  boot();
})();
