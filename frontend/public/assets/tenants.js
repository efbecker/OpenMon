// OpenMon - cadastro de tenants. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, slugify } = window.OpenMon;
  let tenants = [];
  let canManage = false;
  let editing = null;      // tenant em edição (null = novo)
  let slugTouched = false;

  function render() {
    const q = $("filter").value.trim().toLowerCase();
    const rows = tenants.filter((t) => !q || t.name.toLowerCase().includes(q) || t.slug.includes(q));
    $("table").tBodies[0].replaceChildren(...rows.map((t) => {
      const name = el("td", { text: t.name });
      if (t.is_provider) name.append(" ", el("span", { cls: "tag tag-you", text: "datacenter" }));
      const status = el("td", null, el("span", { cls: "tag " + (t.is_active ? "tag-ok" : "tag-off"),
        text: t.is_active ? "ativo" : "desativado" }));
      const act = el("td");
      act.append(button("Usuários", "ghost", () => location.assign(`/usuarios.html?tenant=${t.id}`)));
      if (canManage) act.append(" ", button("Editar", "ghost", () => openForm(t)));
      return el("tr", { cls: t.is_active ? "" : "row-off" }, name, el("td", { cls: "mono", text: t.slug }), status,
        el("td", { text: t.users }), el("td", { text: t.assets }), el("td", { text: t.integrations }),
        el("td", { text: t.backup_sla_hours ? `${t.backup_sla_hours} h` : "—" }),
        el("td", { text: t.contact_email || "—" }), act);
    }));
    $("count").textContent = tenants.length ? `(${tenants.length})` : "";
    $("empty").hidden = rows.length > 0;
  }

  async function load() {
    try {
      const d = await api("GET", "/api/admin/tenants");
      tenants = d.tenants;
      canManage = d.can_manage;
      $("btn-new").hidden = !canManage;
      showError("list-error", "");
      render();
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
      showError("list-error", e.message);
    }
  }

  function openForm(t) {
    editing = t || null;
    slugTouched = !!t;
    $("dlg-title").textContent = t ? `Editar ${t.name}` : "Novo tenant";
    $("f-name").value = t ? t.name : "";
    $("f-slug").value = t ? t.slug : "";
    $("f-sla").value = t && t.backup_sla_hours ? t.backup_sla_hours : "";
    $("f-email").value = t ? t.contact_email || "" : "";
    $("f-notes").value = t ? t.notes || "" : "";
    $("f-active").checked = t ? t.is_active : true;
    $("f-active").disabled = !!(t && t.is_provider);
    $("btn-delete").hidden = !t || t.is_provider;
    showError("form-error", "");
    $("dlg").showModal();
    $("f-name").focus();
  }

  $("f-name").addEventListener("input", () => { if (!slugTouched) $("f-slug").value = slugify($("f-name").value); });
  $("f-slug").addEventListener("input", () => { slugTouched = true; });

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    const sla = $("f-sla").value.trim();
    const body = {
      name: $("f-name").value.trim(),
      slug: $("f-slug").value.trim().toLowerCase(),
      contact_email: $("f-email").value.trim() || null,
      backup_sla_hours: sla ? Number(sla) : null,
      notes: $("f-notes").value.trim() || null,
      is_active: $("f-active").checked,
    };
    if (!body.name || !body.slug) return showError("form-error", "Informe o nome e o identificador.");
    if (editing && editing.is_active && !body.is_active && editing.users > 0 &&
        !confirm(`Desativar ${editing.name}? Os ${editing.users} usuário(s) Cliente vinculados deixam de entrar.`)) return;
    $("btn-save").disabled = true;
    try {
      if (editing) await api("PUT", `/api/admin/tenants/${editing.id}`, body);
      else await api("POST", "/api/admin/tenants", body);
      $("dlg").close();
      await load();
    } catch (e) {
      showError("form-error", e.message);
    } finally {
      $("btn-save").disabled = false;
    }
  });

  $("btn-delete").addEventListener("click", async () => {
    if (!editing) return;
    const typed = prompt(`Excluir o tenant ${editing.name} definitivamente? Digite o identificador "${editing.slug}" para confirmar.`);
    if (typed === null) return;
    if (typed.trim() !== editing.slug) return showError("form-error", "Identificador não confere; nada foi excluído.");
    try {
      await api("DELETE", `/api/admin/tenants/${editing.id}`);
      $("dlg").close();
      await load();
    } catch (e) {
      showError("form-error", e.message);
    }
  });

  $("btn-cancel").addEventListener("click", () => $("dlg").close());
  $("btn-new").addEventListener("click", () => openForm(null));
  $("filter").addEventListener("input", render);

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.scope !== "global") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  })();
})();
