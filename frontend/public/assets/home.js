// OpenMon - página inicial após o login. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, boot, when, ROLE } = window.OpenMon;

  function stat(k, v) {
    return el("div", { cls: "stat" }, el("div", { cls: "k", text: k }), el("div", { cls: "v", text: v }));
  }

  (async function () {
    const data = await boot();
    if (!data) return;
    const u = data.user;
    const name = u.display_name || u.username;
    $("welcome").textContent = `Bem-vindo ao OpenMon, ${name}`;
    $("session-exp").textContent = data.expires_at ? `Sessão expira em ${when(data.expires_at)} (ou após 30 min sem uso)` : "";
    let version = "";
    try {
      const h = await fetch("/api/health", { cache: "no-store" });
      version = (await h.json()).version || "";
    } catch (_) { /* opcional */ }
    $("stats").replaceChildren(
      stat("Usuário", u.username),
      stat("Perfil", ROLE[u.role] || u.role_name || u.role),
      stat("Escopo", u.scope === "global" ? "todos os tenants" : (u.tenants || []).join(", ") || "nenhum tenant ativo"),
      stat("Último login", when(u.last_login_at, "primeiro acesso")),
      stat("Versão", version || "—"),
    );
    $("admin-steps").hidden = u.role !== "global_admin";
    $("hero-admin").hidden = u.role !== "global_admin";
    $("hero-badge").hidden = u.role !== "global_admin";
    $("hero-client").hidden = u.role === "global_admin";
    $("home").hidden = false;
  })();
})();
