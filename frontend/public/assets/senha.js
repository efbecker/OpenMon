// OpenMon - troca da própria senha. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, api, boot, showError } = window.OpenMon;
  let username = "";

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    const current = $("f-current").value;
    const next = $("f-new").value;
    if (!current || !next) return showError("form-error", "Preencha a senha atual e a nova.");
    if (next !== $("f-new2").value) return showError("form-error", "A confirmação não confere com a nova senha.");
    if (next.length < 12) return showError("form-error", "A nova senha precisa ter pelo menos 12 caracteres.");
    if (username && next.toLowerCase().includes(username.toLowerCase())) {
      return showError("form-error", "A senha não pode conter o nome de usuário.");
    }
    $("btn-save").disabled = true;
    try {
      const out = await api("POST", "/api/auth/password", { current_password: current, new_password: next });
      location.replace(out.redirect || "/home.html");
    } catch (e) {
      showError("form-error", e.message);
      $("btn-save").disabled = false;
    }
  });

  (async function () {
    const me = await boot({ allowPasswordChange: true });
    if (!me) return;
    const u = me.user;
    username = u.username;
    $("f-username").value = u.username;
    if (u.auth_source === "ldap") { $("ldap").hidden = false; return; }
    $("must-note").hidden = !u.must_change_password;
    $("intro").hidden = u.must_change_password;
    $("back").hidden = u.must_change_password;
    $("main").hidden = false;
    $("f-current").focus();
  })();
})();
