// OpenMon - integrações de coleta (vCenter, Hyper-V, Veeam, SNMP). Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const KIND = { vmware_vcenter: "VMware vCenter", vmware_vcd: "VMware vCloud Director", hyperv: "Hyper-V (WinRM)", veeam: "Veeam B&R", snmp: "SNMP" };
  const PORT = { vmware_vcenter: 443, vmware_vcd: 443, hyperv: 5986, veeam: 9419, snmp: 161 };
  const INTERVAL = { vmware_vcenter: 60, vmware_vcd: 300, hyperv: 60, veeam: 300, snmp: 60 };
  const USER_LABEL = { vmware_vcenter: "Usuário (ex.: openmon@vsphere.local)",
    vmware_vcd: "Usuário (usuario@System, ou usuario@Org)", hyperv: "Usuário (DOMINIO\\usuario)",
    veeam: "Usuário (DOMINIO\\usuario)" };
  const STATUS = { ok: ["tag-ok", "ok"], warning: ["tag-auto", "aviso"], error: ["tag-bad", "erro"] };
  const DETAIL = { uptime_days: "No ar há (dias)", ip: "IP", vendor: "Fabricante", version: "Versão", build: "Build",
    product: "Produto", api_version: "Versão da API", provider: "Conta do provedor", orgs: "Organizações",
    vdcs: "VDCs", orgs_matched: "Organizações no filtro", vms: "VMs", hosts: "Hosts", datastores: "Datastores", jobs: "Jobs", repositories: "Repositórios",
    organizations: "Quotas de organização (vCloud)", diagnostic: "Diagnóstico", api: "API" };
  let items = [];
  let tenants = [];
  let canManage = false;
  let editing = null;

  function flash(msg) {
    $("list-ok").textContent = msg;
    $("list-ok").hidden = !msg;
  }

  function statusTag(i) {
    if (!i.is_enabled) return el("span", { cls: "tag tag-off", text: "desabilitada" });
    if (!i.last_status) return el("span", { cls: "tag tag-off", text: "aguardando 1ª coleta" });
    const [cls, label] = STATUS[i.last_status] || ["tag-off", i.last_status];
    return el("span", { cls: "tag " + cls, text: label, title: i.last_error || "" });
  }

  function render() {
    const kind = $("filter-kind").value;
    const rows = items.filter((i) => !kind || i.kind === kind);
    $("table").tBodies[0].replaceChildren(...rows.map((i) => {
      const act = el("td");
      if (canManage) {
        const poll = button("Coletar agora", "ghost", () => pollNow(i, poll));
        act.append(poll, button("Editar", "ghost", () => openForm(i)));
      }
      const last = el("td", { cls: "small" }, when(i.last_poll_finished_at, "nunca"));
      if (i.last_poll_duration_ms !== null && i.last_poll_finished_at) last.append(el("span", { cls: "muted", text: ` · ${(i.last_poll_duration_ms / 1000).toFixed(1)} s` }));
      const st = el("td", null, statusTag(i));
      if (i.last_error) st.append(el("div", { cls: "muted small err-line", text: i.last_error, title: i.last_error }));
      return el("tr", { cls: i.is_enabled ? (i.last_status === "error" ? "row-warn" : "") : "row-off" },
        el("td", null, el("strong", { text: i.name })), el("td", { text: KIND[i.kind] || i.kind }),
        el("td", { cls: "mono small", text: `${i.endpoint}:${i.port}` }), el("td", { text: i.tenant_name }),
        el("td", null, i.assets ? el("a", { text: String(i.assets), attrs: { href: `/inventario.html?integration=${i.id}` } }) : "0"),
        el("td", { text: `${i.poll_interval_seconds} s` }), last, st, act);
    }));
    $("count").textContent = items.length ? `(${items.length})` : "";
    $("empty").hidden = items.length > 0;
  }

  async function load() {
    try {
      const [d, t] = await Promise.all([api("GET", "/api/admin/integrations"), api("GET", "/api/admin/tenants")]);
      items = d.integrations;
      canManage = d.can_manage;
      tenants = t.tenants;
      $("btn-new").hidden = !canManage;
      showError("list-error", "");
      render();
      await loadRules();
    } catch (e) {
      if (e.status === 403) { $("main").hidden = true; $("denied").hidden = false; return; }
      showError("list-error", e.message);
    }
  }

  async function pollNow(i, btn) {
    btn.disabled = true;
    btn.textContent = "Coletando…";
    flash("");
    showError("list-error", "");
    try {
      const r = await api("POST", `/api/admin/integrations/${i.id}/poll`);
      if (r.status === "error") showError("list-error", `${i.name}: ${r.message}`);
      else flash(`${i.name}: coleta ${r.status === "ok" ? "concluída" : "com aviso"}${r.message ? " · " + r.message : ""}.`);
      await load();
    } catch (e) {
      showError("list-error", e.message);
      btn.disabled = false;
      btn.textContent = "Coletar agora";
    }
  }

  // --------------------------------------------------------- regras de tenant
  const FIELD = { folder: "Pasta / organização do vCloud", resource_pool: "Resource pool", cluster: "Cluster",
    hyperv_host: "Host Hyper-V", veeam_job: "Job do Veeam", name_regex: "Nome (regex)", vsphere_tag: "Tag do vSphere" };
  const PLACEHOLDER = { folder: "Clientes/ACME* ou ORG-DO-CLIENTE*", resource_pool: "ACME*", cluster: "CL-CLIENTES-*",
    hyperv_host: "hv0?.empresa.local", veeam_job: "ACME - *", name_regex: "^acme-" };
  let rules = [];
  let editingRule = null;

  function resetRuleForm() {
    editingRule = null;
    $("r-priority").value = "100";
    $("r-pattern").value = "";
    $("r-save").textContent = "Adicionar regra";
    $("r-pattern").placeholder = PLACEHOLDER[$("r-field").value] || "";
  }

  function renderRules() {
    const tSel = $("r-tenant");
    const cur = tSel.value;
    tSel.replaceChildren(...tenants.filter((t) => t.is_active).map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
    if (cur) tSel.value = cur;
    const iSel = $("r-integration");
    const icur = iSel.value;
    iSel.replaceChildren(el("option", { text: "Todas as integrações", attrs: { value: "" } }),
      ...items.filter((i) => i.kind !== "snmp").map((i) => el("option", { text: `${i.name} (${KIND[i.kind]})`, attrs: { value: String(i.id) } })));
    iSel.value = icur;
    $("rules").tBodies[0].replaceChildren(...rules.map((r) => {
      const on = el("input", { attrs: { type: "checkbox", "aria-label": "Regra ativa" } });
      on.checked = r.is_enabled;
      on.addEventListener("change", () => saveRule(r.id, Object.assign(ruleBody(r), { is_enabled: on.checked })));
      const act = el("td", null, button("Editar", "ghost", () => {
        editingRule = r;
        $("r-priority").value = r.priority;
        $("r-field").value = r.match_field;
        $("r-pattern").value = r.pattern;
        $("r-tenant").value = String(r.tenant_id);
        $("r-integration").value = r.integration_id ? String(r.integration_id) : "";
        $("r-save").textContent = "Salvar regra";
        $("r-pattern").focus();
      }), button("Excluir", "ghost", async () => {
        if (!confirm(`Excluir a regra "${r.pattern}" → ${r.tenant_name}? Os ativos já atribuídos ficam onde estão até a próxima coleta.`)) return;
        try { await api("DELETE", `/api/admin/tenant-rules/${r.id}`); await loadRules(); } catch (e) { showError("rules-error", e.message); }
      }));
      return el("tr", { cls: r.is_enabled ? "" : "row-off" }, el("td", { cls: "mono", text: String(r.priority) }),
        el("td", { text: FIELD[r.match_field] || r.match_field }), el("td", { cls: "mono", text: r.pattern }),
        el("td", { text: r.tenant_name }), el("td", { text: r.integration_name || "todas" }), el("td", null, on), act);
    }));
    $("rules-count").textContent = rules.length ? `(${rules.length})` : "";
    $("rules-empty").hidden = rules.length > 0;
  }

  function ruleBody(r) {
    return { tenant_id: r.tenant_id, integration_id: r.integration_id, match_field: r.match_field, pattern: r.pattern,
      priority: r.priority, is_enabled: r.is_enabled };
  }

  async function saveRule(id, body) {
    showError("rules-error", "");
    try {
      if (id) await api("PUT", `/api/admin/tenant-rules/${id}`, body);
      else await api("POST", "/api/admin/tenant-rules", body);
      resetRuleForm();
      await loadRules();
    } catch (e) {
      showError("rules-error", e.message);
    }
  }

  async function loadRules() {
    if (!canManage) return;
    try {
      rules = (await api("GET", "/api/admin/tenant-rules")).rules;
      $("rules-card").hidden = false;
      renderRules();
    } catch (e) {
      showError("rules-error", e.message);
    }
  }

  $("r-field").addEventListener("change", () => { $("r-pattern").placeholder = PLACEHOLDER[$("r-field").value] || ""; });
  $("rule-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const body = { priority: Number($("r-priority").value) || 100, match_field: $("r-field").value,
      pattern: $("r-pattern").value.trim(), tenant_id: Number($("r-tenant").value),
      integration_id: $("r-integration").value ? Number($("r-integration").value) : null,
      is_enabled: editingRule ? editingRule.is_enabled : true };
    if (!body.pattern || !body.tenant_id) return showError("rules-error", "Informe o padrão e o tenant.");
    saveRule(editingRule ? editingRule.id : null, body);
  });

  // ------------------------------------------------------------- formulário
  function syncKind() {
    const kind = $("f-kind").value;
    const v3 = $("f-version").value === "3";
    document.querySelectorAll("#form [data-kinds]").forEach((n) => {
      let show = n.getAttribute("data-kinds").split(" ").includes(kind);
      const snmp = n.getAttribute("data-snmp");
      if (show && snmp) show = (snmp === "3") === v3;
      n.hidden = !show;
    });
    const token = kind === "vmware_vcd" && $("f-vcd-auth").value === "token";
    $("l-user").textContent = token ? "Organização do token (System para o provedor)" : USER_LABEL[kind] || "Usuário";
    $("l-secret").textContent = token ? "API token" : "Senha";
    $("f-api-version").placeholder = kind === "vmware_vcd" ? "38.0" : "1.1-rev1";
    $("l-endpoint").textContent = kind === "hyperv" ? "Host ou cluster (DNS ou IP)" : "Endereço (DNS ou IP)";
    $("f-endpoint").placeholder = { snmp: "10.0.0.1", vmware_vcenter: "vcenter.empresa.local", vmware_vcd: "vcloud.empresa.com.br", hyperv: "hv01.empresa.local", veeam: "veeam.empresa.local" }[kind];
    $("f-auth-pw").disabled = !$("f-auth-proto").value;
    $("f-priv-proto").disabled = !$("f-auth-proto").value;
    if ($("f-priv-proto").disabled) $("f-priv-proto").value = "";
    $("f-priv-pw").disabled = !$("f-priv-proto").value;
    const t = tenants.find((x) => String(x.id) === $("f-tenant").value);
    $("tenant-hint").textContent = kind === "snmp"
      ? (t && t.is_provider ? "O equipamento fica do datacenter; dá para entregar interfaces a clientes no Inventário." : "O equipamento e as interfaces ficam visíveis para este cliente.")
      : "Dono padrão dos ativos descobertos (VMs etc.); regras por nome podem distribuir entre tenants.";
  }

  function fillTenants(selected) {
    const sel = $("f-tenant");
    sel.replaceChildren(...tenants.filter((t) => t.is_active || t.id === selected)
      .map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
    const provider = tenants.find((t) => t.is_provider);
    sel.value = String(selected || (provider ? provider.id : ""));
  }

  function openForm(i) {
    editing = i || null;
    const o = (i && i.options) || {};
    $("form-title").textContent = i ? `Editar ${i.name}` : "Nova integração";
    $("f-kind").value = i ? i.kind : "snmp";
    $("f-kind").disabled = !!i;
    $("f-enabled").checked = i ? i.is_enabled : true;
    $("f-name").value = i ? i.name : "";
    $("f-endpoint").value = i ? i.endpoint : "";
    $("f-port").value = i ? i.port : PORT[$("f-kind").value];
    $("f-interval").value = i ? i.poll_interval_seconds : INTERVAL[$("f-kind").value];
    fillTenants(i ? i.tenant_id : null);
    $("f-asset-type").value = o.asset_type || "network_switch";
    $("f-version").value = o.version || "2c";
    $("f-transport").value = o.transport || "ntlm";
    $("f-hosts").value = (o.hosts || []).join("\n");
    $("f-https").checked = o.https !== false;
    $("f-api-version").value = o.api_version || "";
    $("f-veeam-api").value = o.api || "auto";
    $("f-vcd-auth").value = o.auth || "password";
    $("f-orgs").value = (o.orgs || []).join("\n");
    $("f-timeout").value = o.timeout_ms || 2000;
    $("f-retries").value = o.retries !== undefined ? o.retries : 2;
    $("f-discovery").value = o.discovery_minutes || 15;
    $("f-community").value = "";
    $("f-v3-user").value = i && i.kind === "snmp" ? i.username : "";
    $("f-context").value = i ? i.context : "";
    $("f-auth-proto").value = i && i.kind === "snmp" && o.version === "3" ? (i.auth_protocol || "") : "sha256";
    $("f-priv-proto").value = i && i.kind === "snmp" && o.version === "3" ? (i.priv_protocol || "") : "aes";
    $("f-auth-pw").value = "";
    $("f-priv-pw").value = "";
    $("f-user").value = i && i.kind !== "snmp" ? i.username : "";
    $("f-secret").value = "";
    $("f-verify").checked = i ? i.verify_tls : true;
    $("f-ca").value = i ? i.ca_cert_pem : "";
    document.querySelectorAll(".secret-hint").forEach((h) => { h.hidden = !(i && i.has_secret); });
    $("btn-delete").hidden = !i;
    $("test-result").hidden = true;
    showError("form-error", "");
    syncKind();
    $("editor").hidden = false;
    $("editor").scrollIntoView({ behavior: "smooth", block: "start" });
    $("f-name").focus({ preventScroll: true });
  }

  function body() {
    const kind = $("f-kind").value;
    const b = {
      kind, name: $("f-name").value.trim(), tenant_id: Number($("f-tenant").value),
      endpoint: $("f-endpoint").value.trim(), port: Number($("f-port").value) || null,
      poll_interval_seconds: Number($("f-interval").value) || null, is_enabled: $("f-enabled").checked,
      verify_tls: $("f-verify").checked, ca_cert_pem: $("f-ca").value.trim() || null, options: {},
    };
    if (kind === "snmp") {
      b.options = { version: $("f-version").value, asset_type: $("f-asset-type").value, timeout_ms: Number($("f-timeout").value),
        retries: Number($("f-retries").value), discovery_minutes: Number($("f-discovery").value) };
      b.verify_tls = true;
      b.ca_cert_pem = null;
      if (b.options.version === "2c") {
        b.secret = $("f-community").value || null;
      } else {
        b.username = $("f-v3-user").value.trim();
        b.context = $("f-context").value.trim() || null;
        b.auth_protocol = $("f-auth-proto").value || null;
        b.auth_password = $("f-auth-pw").value || null;
        b.priv_protocol = $("f-priv-proto").value || null;
        b.priv_password = $("f-priv-pw").value || null;
      }
    } else {
      b.username = $("f-user").value.trim();
      b.secret = $("f-secret").value || null;
      if (kind === "hyperv") {
        b.options = { transport: $("f-transport").value, https: $("f-https").checked,
          hosts: $("f-hosts").value.split(/\s+/).map((h) => h.trim()).filter(Boolean) };
      } else if (kind === "veeam") {
        b.options = { api: $("f-veeam-api").value, api_version: $("f-api-version").value.trim() || null };
      } else if (kind === "vmware_vcd") {
        b.options = { api_version: $("f-api-version").value.trim() || null, auth: $("f-vcd-auth").value,
          orgs: $("f-orgs").value.split(/\n+/).map((x) => x.trim()).filter(Boolean) };
      }
    }
    return b;
  }

  // Enterprise Manager escuta na 9398 e a API do VBR na 9419: troca a porta se ela ainda é a padrão da outra
  $("f-veeam-api").addEventListener("change", () => {
    const api = $("f-veeam-api").value, port = $("f-port").value;
    if (api === "em" && port === "9419") $("f-port").value = 9398;
    if (api === "vbr" && port === "9398") $("f-port").value = 9419;
  });

  $("f-kind").addEventListener("change", () => {
    const kind = $("f-kind").value;
    $("f-port").value = PORT[kind];
    $("f-interval").value = INTERVAL[kind];
    syncKind();
  });
  $("f-https").addEventListener("change", () => {
    if ($("f-kind").value === "hyperv") $("f-port").value = $("f-https").checked ? 5986 : 5985;
  });
  ["f-version", "f-auth-proto", "f-priv-proto", "f-tenant", "f-vcd-auth"].forEach((id) => $(id).addEventListener("change", syncKind));
  $("filter-kind").addEventListener("change", render);

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("form-error", "");
    const b = body();
    if (!b.name || !b.endpoint || !b.tenant_id) return showError("form-error", "Preencha nome, endereço e tenant.");
    $("btn-save").disabled = true;
    try {
      if (editing) await api("PUT", `/api/admin/integrations/${editing.id}`, b);
      else await api("POST", "/api/admin/integrations", b);
      flash(`Integração ${b.name} salva. A primeira coleta começa em alguns segundos.`);
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
    b.integration_id = editing ? editing.id : null;
    if (!b.name) b.name = "teste";
    const box = $("test-result");
    box.hidden = false;
    box.replaceChildren(el("p", { cls: "muted small", text: "Testando…" }));
    $("btn-test").disabled = true;
    try {
      const r = await api("POST", "/api/admin/integrations/test", b);
      if (!r.ok) {
        box.replaceChildren(el("p", { cls: "error-text", text: "✗ " + (r.error || "falhou") }));
        return;
      }
      const dl = el("dl");
      Object.entries(r.details || {}).forEach(([k, v]) => {
        if (v === null || v === undefined || v === "") return;
        dl.append(el("dt", { text: DETAIL[k] || k }), el("dd", { text: Array.isArray(v) ? v.join(", ") : String(v) }));
      });
      box.replaceChildren(el("p", { cls: "ok-text", text: "✓ " + (r.summary || "conectou") }), dl);
    } catch (e) {
      box.replaceChildren(el("p", { cls: "error-text", text: e.message }));
    } finally {
      $("btn-test").disabled = false;
    }
  });

  $("btn-delete").addEventListener("click", async () => {
    if (!editing) return;
    if (!confirm(`Excluir ${editing.name}? A coleta para e os ${editing.assets} ativo(s) saem do inventário (o histórico de métricas fica).`)) return;
    try {
      await api("DELETE", `/api/admin/integrations/${editing.id}`);
      flash(`Integração ${editing.name} excluída.`);
      $("editor").hidden = true;
      await load();
    } catch (e) {
      showError("form-error", e.message);
    }
  });

  $("btn-cancel").addEventListener("click", () => { $("editor").hidden = true; });
  $("btn-new").addEventListener("click", () => openForm(null));
  resetRuleForm();

  Object.entries(KIND).forEach(([k, label]) => {
    $("f-kind").append(el("option", { text: label, attrs: { value: k } }));
    $("filter-kind").append(el("option", { text: label, attrs: { value: k } }));
  });

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.scope !== "global") { $("denied").hidden = false; return; }
    $("main").hidden = false;
    load();
  })();
})();
