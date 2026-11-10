// OpenMon - cadastro de usuários. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when, randomPassword, ROLE } = window.OpenMon;
  let users = [];
  let tenants = [];
  let roles = [];
  let you = null;
  let editing = null;      // usuário em edição (null = novo)
  let pwTarget = null;

  const roleScope = (code) => (roles.find((r) => r.code === code) || {}).scope;

  function flash(msg) {
    $("list-ok").textContent = msg;
    $("list-ok").hidden = !msg;
  }

  function render() {
    const q = $("filter").value.trim().toLowerCase();
    const tf = $("tenant-filter").value;
    const rows = users.filter((u) =>
      (!q || [u.username, u.display_name, u.email].some((v) => v && v.toLowerCase().includes(q))) &&
      (!tf || u.tenants.some((t) => String(t.id) === tf)));
    $("table").tBodies[0].replaceChildren(...rows.map((u) => {
      const name = el("td", { cls: "mono", text: u.username });
      if (u.id === you) name.append(" ", el("span", { cls: "tag tag-you", text: "você" }));
      if (u.auth_source === "ldap") name.append(" ", el("span", { cls: "tag tag-auto", text: "AD" }));
      const tcell = el("td");
      if (u.scope === "global") tcell.append(el("span", { cls: "muted", text: "todos" }));
      else u.tenants.forEach((t) => tcell.append(el("span", { cls: "tag " + (t.is_active ? "tag-tenant" : "tag-off"), text: t.name }), " "));
      const st = el("td");
      st.append(el("span", { cls: "tag " + (u.is_active ? "tag-ok" : "tag-off"), text: u.is_active ? "ativo" : "desativado" }));
      if (u.locked) st.append(" ", el("span", { cls: "tag tag-bad", text: "bloqueado" }));
      if (u.must_change_password) st.append(" ", el("span", { cls: "tag tag-auto", text: "troca de senha pendente" }));
      const act = el("td");
      if (u.locked) act.append(button("Desbloquear", "ghost", () => unlock(u)), " ");
      if (u.id !== you && u.auth_source === "local") act.append(button("Senha", "ghost", () => openPw(u)), " ");
      act.append(button("Editar", "ghost", () => openForm(u)));
      return el("tr", { cls: u.is_active ? "" : "row-off" }, name, el("td", { text: u.display_name || "—" }),
        el("td", { text: ROLE[u.role] || u.role_name }), tcell, st,
        el("td", { text: when(u.last_login_at, "nunca"), title: u.last_login_ip || "" }), act);
    }));
    $("count").textContent = users.length ? `(${users.length})` : "";
    $("empty").hidden = rows.length > 0;
  }

  async function load() {
    try {
      const [u, t, r] = await Promise.all([api("GET", "/api/admin/users"), api("GET", "/api/admin/tenants"),
        roles.length ? Promise.resolve({ roles }) : api("GET", "/api/admin/roles")]);
      users = u.users;
      you = u.you;
      tenants = t.tenants;
      roles = r.roles;
      const sel = $("tenant-filter");
      const keep = sel.value || new URLSearchParams(location.search).get("tenant") || "";
      sel.replaceChildren(el("option", { text: "Todos os tenants", attrs: { value: "" } }),
        ...tenants.map((x) => el("option", { text: x.name, attrs: { value: String(x.id) } })));
      sel.value = tenants.some((x) => String(x.id) === keep) ? keep : "";
      showError("list-error", "");
      render();
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
      showError("list-error", e.message);
    }
  }

  // ---------------------------------------------------------------- formulário
  function renderTenantChecks(selected) {
    const q = $("f-tenant-filter").value.trim().toLowerCase();
    $("f-tenants").replaceChildren(...tenants.map((t) => {
      const box = el("input", { attrs: { type: "checkbox", value: String(t.id) } });
      box.checked = selected.has(t.id);
      box.addEventListener("change", () => { if (box.checked) selected.add(t.id); else selected.delete(t.id); });
      const label = el("label", { cls: "check" }, box, el("span", { text: t.name }),
        t.is_active ? null : el("span", { cls: "muted small", text: " (desativado)" }));
      label.hidden = !!q && !t.name.toLowerCase().includes(q) && !t.slug.includes(q);
      return label;
    }));
  }

  let selectedTenants = new Set();

  function syncRole() {
    const global = roleScope($("f-role").value) === "global";
    $("tenants-field").hidden = global;
    $("global-hint").hidden = !global;
  }

  function openForm(u) {
    editing = u || null;
    $("dlg-title").textContent = u ? `Editar ${u.username}` : "Novo usuário";
    $("f-username").value = u ? u.username : "";
    $("f-username").disabled = !!u;
    $("f-display").value = u ? u.display_name || "" : "";
    $("f-email").value = u ? u.email || "" : "";
    $("f-role").replaceChildren(...roles.map((r) => el("option", { text: ROLE[r.code] || r.name, attrs: { value: r.code } })));
    const tf = $("tenant-filter").value;
    $("f-role").value = u ? u.role : "client";
    selectedTenants = new Set(u ? u.tenants.map((t) => t.id) : (tf ? [Number(tf)] : []));
    $("f-tenant-filter").value = "";
    renderTenantChecks(selectedTenants);
    $("password-field").hidden = !!u;
    $("must-change-field").hidden = !!u;
    $("f-password").value = u ? "" : randomPassword();
    $("f-must-change").checked = true;
    $("f-active").checked = u ? u.is_active : true;
    $("btn-delete").hidden = !u || u.id === you;
    syncRole();
    showError("form-error", "");
    $("dlg").showModal();
    (u ? $("f-display") : $("f-username")).focus();
  }

  $("f-role").addEventListener("change", syncRole);
  $("f-tenant-filter").addEventListener("input", () => renderTenantChecks(selectedTenants));
  $("btn-gen").addEventListener("click", () => { $("f-password").value = randomPassword(); });

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    const body = {
      display_name: $("f-display").value.trim() || null,
      email: $("f-email").value.trim() || null,
      role: $("f-role").value,
      tenant_ids: roleScope($("f-role").value) === "global" ? [] : Array.from(selectedTenants),
      is_active: $("f-active").checked,
    };
    if (roleScope(body.role) !== "global" && !body.tenant_ids.length) {
      return showError("form-error", "Selecione pelo menos um tenant para o perfil Cliente.");
    }
    $("btn-save").disabled = true;
    try {
      if (editing) {
        await api("PUT", `/api/admin/users/${editing.id}`, body);
        flash(`Usuário ${editing.username} atualizado.`);
      } else {
        body.username = $("f-username").value.trim();
        body.password = $("f-password").value;
        body.must_change_password = $("f-must-change").checked;
        await api("POST", "/api/admin/users", body);
        flash(`Usuário ${body.username} criado. Repasse a senha inicial por um canal seguro.`);
      }
      $("dlg").close();
      await load();
    } catch (e) {
      showError("form-error", e.message);
    } finally {
      $("btn-save").disabled = false;
    }
  });

  $("btn-delete").addEventListener("click", async () => {
    if (!editing || !confirm(`Excluir o usuário ${editing.username}? A trilha de auditoria é mantida. ` +
      "Para só bloquear o acesso, desmarque \"Ativo\".")) return;
    try {
      await api("DELETE", `/api/admin/users/${editing.id}`);
      flash(`Usuário ${editing.username} excluído.`);
      $("dlg").close();
      await load();
    } catch (e) {
      showError("form-error", e.message);
    }
  });
  $("btn-cancel").addEventListener("click", () => $("dlg").close());
  $("btn-new").addEventListener("click", () => openForm(null));

  // ------------------------------------------------------------------- senha
  function openPw(u) {
    pwTarget = u;
    $("pw-user").textContent = u.username;
    $("pw-password").value = randomPassword();
    $("pw-must-change").checked = true;
    showError("pw-error", "");
    $("dlg-pw").showModal();
  }

  $("pw-gen").addEventListener("click", () => { $("pw-password").value = randomPassword(); });
  $("pw-cancel").addEventListener("click", () => $("dlg-pw").close());
  $("form-pw").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!pwTarget) return;
    $("pw-save").disabled = true;
    try {
      await api("POST", `/api/admin/users/${pwTarget.id}/password`,
        { password: $("pw-password").value, must_change_password: $("pw-must-change").checked });
      flash(`Senha de ${pwTarget.username} redefinida. Repasse-a por um canal seguro.`);
      $("dlg-pw").close();
      await load();
    } catch (e) {
      showError("pw-error", e.message);
    } finally {
      $("pw-save").disabled = false;
    }
  });

  async function unlock(u) {
    try {
      await api("POST", `/api/admin/users/${u.id}/unlock`);
      flash(`Usuário ${u.username} desbloqueado.`);
      await load();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  $("filter").addEventListener("input", render);
  $("tenant-filter").addEventListener("change", () => {
    const v = $("tenant-filter").value;
    history.replaceState(null, "", v ? `?tenant=${v}` : location.pathname);
    render();
  });

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.role !== "global_admin") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  })();
})();
