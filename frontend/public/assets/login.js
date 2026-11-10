// OpenMon - tela de login. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);

  function setError(message) {
    $("login-error").textContent = message || "";
    $("login-error").hidden = !message;
  }

  async function getJson(path) {
    const res = await fetch(path, { headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" });
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    return { ok: res.ok, status: res.status, data };
  }

  async function boot() {
    const me = await getJson("/api/auth/me").catch(() => null);
    if (me && me.ok) return location.replace("/home.html");
    const st = await getJson("/api/setup/status").catch(() => null);
    if (st && st.ok && st.data.setup_open && !st.data.admin_created) $("setup-note").hidden = false;
    const u = new URLSearchParams(location.search).get("u");
    if (u) {
      $("login-username").value = u;
      $("login-password").focus();
    } else {
      $("login-username").focus();
    }
  }

  $("login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    setError("");
    const username = $("login-username").value.trim();
    const password = $("login-password").value;
    if (!username || !password) return setError("Informe usuário e senha.");
    $("btn-login").disabled = true;
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST", cache: "no-store", credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username, password }),
      });
      let data = null;
      try { data = await res.json(); } catch (_) { data = null; }
      if (!res.ok) {
        $("login-password").value = "";
        $("login-password").focus();
        return setError((data && typeof data.detail === "string") ? data.detail : `Erro HTTP ${res.status}`);
      }
      location.replace(data.redirect || "/home.html");
    } catch (_) {
      setError("Não foi possível falar com o servidor.");
    } finally {
      $("btn-login").disabled = false;
    }
  });

  boot();
})();
