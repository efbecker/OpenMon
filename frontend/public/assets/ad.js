// OpenMon - configuração do Active Directory / LDAP. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, ROLE } = window.OpenMon;
  let dirs = [];
  let tenants = [];
  let defaultFilter = "(&(objectClass=user)(sAMAccountName={username}))";
  let editing = null;
  let lastGroups = [];

  function flash(msg) {
    $("list-ok").textContent = msg;
    $("list-ok").hidden = !msg;
  }

  function render() {
    $("table").tBodies[0].replaceChildren(...dirs.map((d) => {
      const act = el("td", null, button("Editar", "ghost", () => openForm(d)));
      return el("tr", { cls: d.is_enabled ? "" : "row-off" }, el("td", { text: d.name }),
        el("td", { cls: "mono small", text: d.urls.join(", ") }),
        el("td", { text: d.security === "ldaps" ? "LDAPS" : "StartTLS" }),
        el("td", { cls: "mono small", text: d.base_dn }), el("td", { text: d.mappings.length }), el("td", { text: d.users }),
        el("td", null, el("span", { cls: "tag " + (d.is_enabled ? "tag-ok" : "tag-off"), text: d.is_enabled ? "habilitado" : "desabilitado" })),
        act);
    }));
    $("count").textContent = dirs.length ? `(${dirs.length})` : "";
    $("empty").hidden = dirs.length > 0;
  }

  async function load() {
    try {
      const [d, t] = await Promise.all([api("GET", "/api/admin/ldap"), api("GET", "/api/admin/tenants")]);
      dirs = d.directories;
      defaultFilter = d.default_filter || defaultFilter;
      tenants = t.tenants;
      showError("list-error", "");
      render();
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
      showError("list-error", e.message);
    }
  }

  // ------------------------------------------------------------ mapeamentos
  function mapRow(m) {
    m = m || { group_dn: "", role: "client", tenant_id: null };
    const dn = el("input", { attrs: { maxlength: "1000", spellcheck: "false", placeholder: "CN=Grupo,OU=Grupos,DC=empresa,DC=local" } });
    dn.value = m.group_dn;
    dn.setAttribute("list", "groups-seen");
    const role = el("select");
    ["global_admin", "operator", "client"].forEach((c) => role.append(el("option", { text: ROLE[c], attrs: { value: c } })));
    role.value = m.role;
    const tenant = el("select");
    tenant.append(el("option", { text: "— escolha —", attrs: { value: "" } }));
    tenants.forEach((t) => tenant.append(el("option", { text: t.name + (t.is_active ? "" : " (desativado)"), attrs: { value: String(t.id) } })));
    tenant.value = m.tenant_id ? String(m.tenant_id) : "";
    const sync = () => { tenant.disabled = role.value !== "client"; if (tenant.disabled) tenant.value = ""; };
    role.addEventListener("change", sync);
    sync();
    const tr = el("tr", { cls: "map-row" }, el("td", { cls: "wide-cell" }, dn), el("td", null, role), el("td", null, tenant));
    tr.append(el("td", null, button("Remover", "ghost", () => tr.remove())));
    tr.read = () => ({ group_dn: dn.value.trim(), role: role.value, tenant_id: tenant.value ? Number(tenant.value) : null });
    return tr;
  }

  function readMappings() {
    return Array.from($("maps").tBodies[0].rows).map((r) => r.read()).filter((m) => m.group_dn);
  }

  function groupsDatalist(groups) {
    let dl = $("groups-seen");
    if (!dl) { dl = el("datalist", { attrs: { id: "groups-seen" } }); document.body.append(dl); }
    dl.replaceChildren(...groups.map((g) => el("option", { attrs: { value: g } })));
  }

  // ------------------------------------------------------------- formulário
  function openForm(d) {
    editing = d || null;
    $("form-title").textContent = d ? `Editar ${d.name}` : "Novo diretório";
    $("f-enabled").checked = d ? d.is_enabled : true;
    $("f-name").value = d ? d.name : "";
    $("f-security").value = d ? d.security : "starttls";
    $("f-urls").value = d ? (d.hosts || d.urls).join(", ") : "";
    $("f-port").value = d ? d.port : 389;
    $("f-verify").checked = d ? d.verify_tls !== false : true;
    $("verify-hint").hidden = $("f-verify").checked;
    $("f-base").value = d ? d.base_dn : "";
    $("f-bind-dn").value = d ? d.bind_dn : "";
    $("f-bind-pw").value = "";
    $("pw-hint").hidden = !(d && d.has_password);
    $("f-filter").value = d ? d.user_filter : defaultFilter;
    $("f-group-attr").value = d ? d.group_attribute : "memberOf";
    $("f-timeout").value = d ? d.timeout_seconds : 5;
    $("f-ca").value = d ? d.ca_cert_pem : "";
    $("maps").tBodies[0].replaceChildren(...(d && d.mappings.length ? d.mappings : [null]).map(mapRow));
    $("btn-delete").hidden = !d;
    $("test-result").hidden = true;
    lastGroups = [];
    groupsDatalist([]);
    showError("form-error", "");
    $("editor").hidden = false;
    $("editor").scrollIntoView({ behavior: "smooth", block: "start" });
    $("f-name").focus({ preventScroll: true });
  }

  function body() {
    return {
      name: $("f-name").value.trim(),
      is_enabled: $("f-enabled").checked,
      urls: $("f-urls").value.split(/[\s,;]+/).map((u) => u.trim()).filter(Boolean),
      security: $("f-security").value,
      port: Number($("f-port").value) || null,
      verify_tls: $("f-verify").checked,
      base_dn: $("f-base").value.trim(),
      bind_dn: $("f-bind-dn").value.trim(),
      bind_password: $("f-bind-pw").value || null,
      user_filter: $("f-filter").value.trim() || defaultFilter,
      group_attribute: $("f-group-attr").value.trim(),
      ca_cert_pem: $("f-ca").value.trim() || null,
      timeout_seconds: Number($("f-timeout").value) || 5,
      mappings: readMappings(),
    };
  }

  $("f-security").addEventListener("change", () => {
    $("f-port").value = $("f-security").value === "ldaps" ? 636 : 389;
  });
  $("f-verify").addEventListener("change", () => { $("verify-hint").hidden = $("f-verify").checked; });

  $("btn-add-map").addEventListener("click", () => $("maps").tBodies[0].append(mapRow(null)));

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    const b = body();
    if (!b.name || !b.urls.length || !b.base_dn || !b.bind_dn) return showError("form-error", "Preencha nome, servidores, Base DN e conta de serviço.");
    if (!b.mappings.length && !confirm("Nenhum grupo mapeado: ninguém do AD vai conseguir entrar. Salvar assim mesmo?")) return;
    $("btn-save").disabled = true;
    try {
      if (editing) await api("PUT", `/api/admin/ldap/${editing.id}`, b);
      else await api("POST", "/api/admin/ldap", b);
      flash(`Diretório ${b.name} salvo.`);
      $("editor").hidden = true;
      await load();
    } catch (e) {
      showError("form-error", e.message);
    } finally {
      $("btn-save").disabled = false;
    }
  });

  $("btn-test").addEventListener("click", async () => {
    showError("form-error", "");
    const b = body();
    b.directory_id = editing ? editing.id : null;
    b.test_username = $("t-user").value.trim() || null;
    b.test_password = $("t-pw").value || null;
    const box = $("test-result");
    box.hidden = false;
    box.replaceChildren(el("p", { cls: "muted small", text: "Testando…" }));
    $("btn-test").disabled = true;
    try {
      const r = await api("POST", "/api/admin/ldap/test", b);
      const list = el("ul", { cls: "test-steps" }, ...r.steps.map((s) =>
        el("li", { cls: s.ok ? "good" : "bad" }, el("strong", { text: (s.ok ? "✓ " : "✗ ") + s.step }), s.detail ? el("span", { cls: "muted", text: " · " + s.detail }) : null)));
      box.replaceChildren(list);
      if (r.groups) {
        lastGroups = r.groups;
        groupsDatalist(r.groups);
        box.append(el("p", { cls: "small", text: `Grupos de ${b.test_username} (${r.groups.length}):` }));
        const ul = el("ul", { cls: "group-list" });
        r.groups.forEach((g) => {
          const li = el("li", null, el("code", { text: g }), " ");
          li.append(button("Mapear", "ghost", () => $("maps").tBodies[0].append(mapRow({ group_dn: g, role: "client", tenant_id: null }))));
          ul.append(li);
        });
        box.append(ul);
        box.append(el("p", { cls: r.access ? "ok-text small" : "error-text small",
          text: r.access ? `Com os mapeamentos atuais: ${ROLE[r.access.role]}` + (r.access.tenants.length ? ` · tenants ${r.access.tenants.join(", ")}` : " · todos os tenants")
            : "Com os mapeamentos atuais, este usuário NÃO teria acesso (nenhum grupo mapeado)." }));
      }
    } catch (e) {
      box.replaceChildren(el("p", { cls: "error-text", text: e.message }));
    } finally {
      $("btn-test").disabled = false;
    }
  });

  $("btn-delete").addEventListener("click", async () => {
    if (!editing) return;
    if (!confirm(`Excluir ${editing.name}? Os ${editing.users} usuário(s) do AD vinculados são desativados e as sessões deles encerradas.`)) return;
    try {
      await api("DELETE", `/api/admin/ldap/${editing.id}`);
      flash(`Diretório ${editing.name} excluído.`);
      $("editor").hidden = true;
      await load();
    } catch (e) {
      showError("form-error", e.message);
    }
  });

  $("btn-cancel").addEventListener("click", () => { $("editor").hidden = true; });
  $("btn-new").addEventListener("click", () => openForm(null));

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.role !== "global_admin") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  })();
})();
