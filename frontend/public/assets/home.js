// OpenMon - página inicial após o login. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  let csrf = "";

  const ROLE = { global_admin: "Administrador global", operator: "Operador", client: "Cliente" };

  function fmt(iso) {
    if (!iso) return "primeiro acesso";
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString("pt-BR");
  }

  function stat(k, v) {
    const box = document.createElement("div");
    box.className = "stat";
    const a = document.createElement("div");
    a.className = "k";
    a.textContent = k;
    const b = document.createElement("div");
    b.className = "v";
    b.textContent = v;
    box.append(a, b);
    return box;
  }

  async function boot() {
    let res;
    try {
      res = await fetch("/api/auth/me", { headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" });
    } catch (_) {
      return location.replace("/login.html");
    }
    if (!res.ok) return location.replace("/login.html");
    const data = await res.json();
    csrf = data.csrf_token;
    const u = data.user;
    const name = u.display_name || u.username;
    $("user-chip").textContent = `${name} · ${ROLE[u.role] || u.role_name || u.role}`;
    $("welcome").textContent = `Bem-vindo ao OpenMon, ${name}`;
    $("session-exp").textContent = data.expires_at ? `Sessão expira em ${fmt(data.expires_at)} (ou após 30 min sem uso)` : "";
    let version = "";
    try {
      const h = await fetch("/api/health", { cache: "no-store" });
      version = (await h.json()).version || "";
    } catch (_) { /* opcional */ }
    $("stats").replaceChildren(
      stat("Usuário", u.username),
      stat("Perfil", ROLE[u.role] || u.role_name || u.role),
      stat("Escopo", u.scope === "global" ? "todos os tenants" : "tenants vinculados"),
      stat("Último login", fmt(u.last_login_at)),
      stat("Versão", version || "—"),
    );
    $("home").hidden = false;
  }

  $("btn-logout").addEventListener("click", async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST", cache: "no-store", credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf, Accept: "application/json" } });
    } catch (_) { /* segue para o login de qualquer forma */ }
    location.replace("/login.html");
  });

  boot();
})();
