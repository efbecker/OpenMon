// OpenMon - configuração de alertas (triggers) e canais. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const SEV = { disaster: "Desastre", high: "Alta", average: "Média", warning: "Atenção", info: "Informação" };
  const SRC = { metric: "Métrica", interface: "Uso de interface", availability: "Fora do ar", backup: "Backup",
    integration: "Integração" };
  const OPS = { ">": "maior que", ">=": "≥", "<": "menor que", "<=": "≤", "=": "=", "<>": "≠" };
  const EXPR = { avg: "média", max: "máximo", min: "mínimo", last: "última" };
  const TYPE = { vcenter: "vCenter", datacenter: "Datacenter", cluster: "Cluster", hypervisor_host: "Host",
    vm: "VM", datastore: "Datastore", network_switch: "Switch", router: "Roteador", firewall: "Firewall",
    storage: "Storage", physical_server: "Servidor físico", backup_server: "Servidor de backup",
    backup_repository: "Repositório de backup", other: "Outro" };
  const KIND = { email: "E-mail", telegram: "Telegram", webhook: "Webhook" };
  const EVENT = { problem: "problema", recovery: "resolvido", ack: "reconhecido", test: "teste" };
  const STORAGE_USED = 52;
  let tdata = { triggers: [], metrics: [], tenants: [], channels: [], asset_types: [] };
  let cdata = { channels: [], tenants: [], deliveries: [] };
  let editingT = null;
  let editingC = null;

  function flash(msg) {
    $("list-ok").textContent = msg;
    $("list-ok").hidden = !msg;
  }

  function metricLabel(m) {
    if (m.id === STORAGE_USED) return "Armazenamento usado (% da capacidade)";
    return `${m.name} (${m.unit})`;
  }

  function unitOf(t) {
    if (t.source === "interface" || t.metric_id === STORAGE_USED) return "%";
    if (t.source === "metric") { const m = tdata.metrics.find((x) => x.id === t.metric_id); return m ? m.unit : ""; }
    return "";
  }

  function condition(t) {
    const win = `${Math.round(t.window_seconds / 60)} min`;
    if (t.source === "availability") return `fora do ar há ${win}`;
    if (t.source === "backup") return t.threshold > 0 ? `falhou ou sem backup bom há ${t.threshold} h` : "falhou ou fora do SLA do tenant";
    if (t.source === "integration") return "integração com erro";
    const what = t.source === "interface" ? "uso da interface" : (t.metric_id === STORAGE_USED ? "armazenamento usado" : (t.metric_name || "métrica"));
    let s = `${what} (${EXPR[t.expression]} ${win}) ${OPS[t.operator]} ${t.threshold} ${unitOf(t)}`;
    if (t.recovery_threshold !== null) s += ` · recupera em ${t.recovery_threshold}`;
    return s;
  }

  // ---------------------------------------------------------------- alertas
  function renderTriggers() {
    const chName = Object.fromEntries(tdata.channels.map((c) => [c.id, c.name]));
    $("table").tBodies[0].replaceChildren(...tdata.triggers.map((t) => {
      const scope = [t.tenant_name || "todos os tenants"];
      if (t.asset_type) scope.push(TYPE[t.asset_type] || t.asset_type);
      if (t.asset_name) scope.push(t.asset_name);
      if (t.interface_name) scope.push(t.interface_name);
      return el("tr", { cls: t.is_enabled ? "" : "row-off" },
        el("td", null, el("strong", { text: t.name }), el("div", { cls: "muted small", text: SRC[t.source] })),
        el("td", { cls: "small wrap", text: condition(t) }), el("td", { cls: "small", text: scope.join(" · ") }),
        el("td", null, el("span", { cls: `sev-tag sev-${t.severity}`, text: SEV[t.severity] })),
        el("td", { cls: "small wrap", text: (t.channel_ids || []).map((id) => chName[id]).filter(Boolean).join(", ") || "—" }),
        el("td", { cls: t.open_problems ? "bad" : "", text: String(t.open_problems) }),
        el("td", null, button("Editar", "ghost", () => openTrigger(t))));
    }));
    $("count").textContent = tdata.triggers.length ? `(${tdata.triggers.length})` : "";
    $("empty").hidden = tdata.triggers.length > 0;
  }

  function syncSource() {
    const src = $("t-source").value;
    document.querySelectorAll("#t-form [data-src]").forEach((n) => { n.hidden = !n.getAttribute("data-src").split(" ").includes(src); });
    const mid = Number($("t-metric").value);
    $("t-unit").textContent = src === "interface" || mid === STORAGE_USED ? "(%)" : src === "metric" ? `(${(tdata.metrics.find((m) => m.id === mid) || {}).unit || ""})` : "";
    $("t-hint").textContent = {
      metric: "Vale para cada ativo do tenant e do tipo escolhidos que tiver essa métrica. VM desligada e host em manutenção não contam.",
      interface: "Interfaces monitoradas: % da banda contratada (link de cliente) ou da velocidade da porta, pelo maior entre entrada e saída.",
      availability: "Equipamento, host ou VM com situação \"fora\" (não responde) há pelo menos esse tempo. VM desligada não é \"fora\".",
      backup: "Um problema por job do Veeam: última execução falhou ou o último backup bom passou do limite.",
      integration: "Um problema só, com a lista das integrações que estão falhando na coleta.",
    }[src];
  }

  function fillSelect(sel, opts, value) {
    sel.replaceChildren(...opts.map(([v, label]) => el("option", { text: label, attrs: { value: String(v) } })));
    sel.value = value === null || value === undefined ? "" : String(value);
  }

  function openTrigger(t) {
    editingT = t || null;
    $("t-title").textContent = t ? `Editar ${t.name}` : "Novo alerta";
    $("t-enabled").checked = t ? t.is_enabled : true;
    $("t-name").value = t ? t.name : "";
    $("t-severity").value = t ? t.severity : "average";
    $("t-source").value = t ? t.source : "metric";
    fillSelect($("t-metric"), tdata.metrics.filter((m) => m.id !== 40).map((m) => [m.id, metricLabel(m)]), t && t.metric_id ? t.metric_id : 1);
    $("t-expr").value = t ? t.expression : "avg";
    const win = t ? Math.round(t.window_seconds / 60) : 5;
    $("t-window").value = win;
    $("t-window-av").value = t && t.source === "availability" ? win : 2;
    $("t-op").value = t ? t.operator : ">";
    $("t-threshold").value = t ? t.threshold : 90;
    $("t-recovery").value = t && t.recovery_threshold !== null ? t.recovery_threshold : "";
    $("t-hours").value = t && t.source === "backup" ? t.threshold : 0;
    fillSelect($("t-tenant"), [["", "Todos os tenants"], ...tdata.tenants.map((x) => [x.id, x.name])], t ? t.tenant_id : null);
    fillSelect($("t-type"), [["", "Todos os tipos"], ...tdata.asset_types.map((x) => [x, TYPE[x] || x])], t ? t.asset_type : null);
    const selected = new Set(t ? t.channel_ids : []);
    $("t-channels").replaceChildren(...tdata.channels.map((c) => {
      const cb = el("input", { attrs: { type: "checkbox", value: String(c.id) } });
      cb.checked = selected.has(c.id);
      return el("label", { cls: "check" }, cb, el("span", { text: `${c.name} · ${KIND[c.kind]}` + (c.tenant_name ? ` (${c.tenant_name})` : "") }));
    }));
    $("t-channels").hidden = !tdata.channels.length;
    $("t-no-channels").hidden = tdata.channels.length > 0;
    $("t-delete").hidden = !t;
    showError("t-error", "");
    syncSource();
    $("t-editor").hidden = false;
    $("t-editor").scrollIntoView({ behavior: "smooth", block: "start" });
    $("t-name").focus({ preventScroll: true });
  }

  function triggerBody() {
    const src = $("t-source").value;
    const b = { name: $("t-name").value.trim(), severity: $("t-severity").value, source: src, is_enabled: $("t-enabled").checked,
      tenant_id: $("t-tenant").value ? Number($("t-tenant").value) : null, metric_id: null, asset_type: null,
      expression: "avg", operator: ">", threshold: 0, recovery_threshold: null, window_seconds: 300,
      channel_ids: Array.from($("t-channels").querySelectorAll("input:checked")).map((c) => Number(c.value)) };
    if (["metric", "interface", "availability"].includes(src) && $("t-type").value) b.asset_type = $("t-type").value;
    if (src === "metric" || src === "interface") {
      if (src === "metric") b.metric_id = Number($("t-metric").value);
      b.expression = $("t-expr").value;
      b.operator = $("t-op").value;
      b.threshold = Number($("t-threshold").value);
      b.recovery_threshold = $("t-recovery").value === "" ? null : Number($("t-recovery").value);
      b.window_seconds = Math.max(1, Number($("t-window").value) || 5) * 60;
    } else if (src === "availability") {
      b.operator = "<";
      b.threshold = 1;
      b.window_seconds = Math.max(1, Number($("t-window-av").value) || 2) * 60;
    } else if (src === "backup") {
      b.threshold = Math.max(0, Number($("t-hours").value) || 0);
    }
    return b;
  }

  $("t-source").addEventListener("change", syncSource);
  $("t-metric").addEventListener("change", syncSource);
  $("t-cancel").addEventListener("click", () => { $("t-editor").hidden = true; });
  $("btn-new").addEventListener("click", () => openTrigger(null));
  $("t-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("t-error", "");
    const b = triggerBody();
    if (!b.name) return showError("t-error", "Dê um nome ao alerta.");
    $("t-save").disabled = true;
    try {
      if (editingT) await api("PUT", `/api/alerts/triggers/${editingT.id}`, b);
      else await api("POST", "/api/alerts/triggers", b);
      flash(`Alerta "${b.name}" salvo. Vale a partir da próxima avaliação (até 30 s).`);
      $("t-editor").hidden = true;
      await loadTriggers();
    } catch (e) {
      showError("t-error", e.message);
    } finally {
      $("t-save").disabled = false;
    }
  });
  $("t-delete").addEventListener("click", async () => {
    if (!editingT || !confirm(`Excluir o alerta "${editingT.name}"? Os problemas abertos dele são fechados.`)) return;
    try {
      await api("DELETE", `/api/alerts/triggers/${editingT.id}`);
      $("t-editor").hidden = true;
      flash("Alerta excluído.");
      await loadTriggers();
    } catch (e) {
      showError("t-error", e.message);
    }
  });
  $("btn-recommended").addEventListener("click", async () => {
    try {
      const r = await api("POST", "/api/alerts/triggers/recommended");
      flash(r.created.length ? `Criados: ${r.created.join(", ")}. Marque os canais em cada um.` : "Os recomendados já existem.");
      await loadTriggers();
    } catch (e) {
      showError("list-error", e.message);
    }
  });

  async function loadTriggers() {
    tdata = await api("GET", "/api/alerts/triggers");
    renderTriggers();
  }

  // ------------------------------------------------------------------ canais
  function destination(c) {
    if (c.kind === "email") return (c.config.to || []).join(", ");
    if (c.kind === "telegram") return `chat ${c.config.chat_id}`;
    return c.config.url || "";
  }

  function renderChannels() {
    $("channels").tBodies[0].replaceChildren(...cdata.channels.map((c) => {
      const test = c.last_test_at ? el("span", { cls: c.last_test_ok ? "good" : "bad", text: (c.last_test_ok ? "✓ " : "✗ ") + when(c.last_test_at) }) : "—";
      return el("tr", { cls: c.is_enabled ? "" : "row-off" }, el("td", null, el("strong", { text: c.name })),
        el("td", { text: KIND[c.kind] }), el("td", { cls: "small mono", text: destination(c), title: destination(c) }),
        el("td", { cls: "small", text: c.tenant_name ? `só ${c.tenant_name}` : "todos os tenants" }),
        el("td", { text: String(c.triggers) }), el("td", { cls: "small" }, test),
        el("td", { cls: c.failed_7d ? "bad" : "", text: String(c.failed_7d) }),
        el("td", null, button("Editar", "ghost", () => openChannel(c))));
    }));
    $("c-count").textContent = cdata.channels.length ? `(${cdata.channels.length})` : "";
    $("c-empty").hidden = cdata.channels.length > 0;
    $("deliveries").tBodies[0].replaceChildren(...cdata.deliveries.map((d) => el("tr", { cls: d.status === "failed" ? "row-warn" : "" },
      el("td", { cls: "small", text: when(d.sent_at || d.created_at) }), el("td", { text: d.channel_name || "—" }),
      el("td", { text: EVENT[d.event] || d.event }), el("td", { cls: "small wrap", text: d.message || "" }),
      el("td", { cls: "small wrap" }, el("span", { cls: "tag " + (d.status === "sent" ? "tag-ok" : d.status === "failed" ? "tag-bad" : "tag-auto"),
        text: d.status === "sent" ? "enviado" : d.status === "failed" ? "falhou" : `na fila (${d.attempts} tentativa(s))` }),
      d.last_error ? el("div", { cls: "muted", text: d.last_error }) : null))));
    $("d-empty").hidden = cdata.deliveries.length > 0;
  }

  function syncKind() {
    const kind = $("c-kind").value;
    document.querySelectorAll("#c-form [data-kind]").forEach((n) => { n.hidden = n.getAttribute("data-kind") !== kind; });
  }

  function openChannel(c) {
    editingC = c || null;
    const cfg = (c && c.config) || {};
    $("c-title").textContent = c ? `Editar ${c.name}` : "Novo canal";
    $("c-enabled").checked = c ? c.is_enabled : true;
    $("c-name").value = c ? c.name : "";
    $("c-kind").value = c ? c.kind : "email";
    $("c-kind").disabled = !!c;
    fillSelect($("c-tenant"), [["", "Todos os tenants (NOC)"], ...cdata.tenants.filter((t) => !t.is_provider).map((t) => [t.id, `Só ${t.name}`])], c ? c.tenant_id : null);
    $("c-host").value = cfg.host || "";
    $("c-security").value = cfg.security || "starttls";
    $("c-port").value = cfg.port || 587;
    $("c-from").value = cfg.from || "";
    $("c-to").value = (cfg.to || []).join("\n");
    $("c-user").value = c ? c.username : "";
    $("c-pw").value = "";
    $("c-token").value = "";
    $("c-chat").value = cfg.chat_id || "";
    $("c-url").value = cfg.url || "";
    $("c-method").value = cfg.method || "POST";
    $("c-secret").value = "";
    $("c-headers").value = Object.entries(cfg.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
    document.querySelectorAll("#c-form .secret-hint").forEach((n) => { n.hidden = !(c && c.has_secret); });
    $("c-delete").hidden = !c;
    $("c-test-result").hidden = true;
    showError("c-error", "");
    syncKind();
    $("c-editor").hidden = false;
    $("c-editor").scrollIntoView({ behavior: "smooth", block: "start" });
    $("c-name").focus({ preventScroll: true });
  }

  function channelBody() {
    const kind = $("c-kind").value;
    const b = { name: $("c-name").value.trim(), kind, is_enabled: $("c-enabled").checked,
      tenant_id: $("c-tenant").value ? Number($("c-tenant").value) : null, config: {}, username: null, secret: null };
    if (kind === "email") {
      b.config = { host: $("c-host").value.trim(), port: Number($("c-port").value) || null, security: $("c-security").value,
        from: $("c-from").value.trim(), to: $("c-to").value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean) };
      b.username = $("c-user").value.trim() || null;
      b.secret = $("c-pw").value || null;
    } else if (kind === "telegram") {
      b.config = { chat_id: $("c-chat").value.trim() };
      b.secret = $("c-token").value.trim() || null;
    } else {
      const headers = {};
      $("c-headers").value.split("\n").forEach((line) => {
        const i = line.indexOf(":");
        if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      });
      b.config = { url: $("c-url").value.trim(), method: $("c-method").value, headers };
      b.secret = $("c-secret").value || null;
    }
    return b;
  }

  $("c-kind").addEventListener("change", syncKind);
  $("c-security").addEventListener("change", () => { $("c-port").value = $("c-security").value === "tls" ? 465 : 587; });
  $("c-cancel").addEventListener("click", () => { $("c-editor").hidden = true; });
  $("c-new").addEventListener("click", () => openChannel(null));
  $("c-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("c-error", "");
    const b = channelBody();
    if (!b.name) return showError("c-error", "Dê um nome ao canal.");
    $("c-save").disabled = true;
    try {
      if (editingC) await api("PUT", `/api/alerts/channels/${editingC.id}`, b);
      else await api("POST", "/api/alerts/channels", b);
      flash(`Canal "${b.name}" salvo. Marque-o nos alertas que devem usá-lo.`);
      $("c-editor").hidden = true;
      await Promise.all([loadChannels(), loadTriggers()]);
    } catch (e) {
      showError("c-error", e.message);
    } finally {
      $("c-save").disabled = false;
    }
  });
  $("c-test").addEventListener("click", async () => {
    showError("c-error", "");
    const b = channelBody();
    if (!b.name) b.name = "teste";
    b.channel_id = editingC ? editingC.id : null;
    const box = $("c-test-result");
    box.hidden = false;
    box.replaceChildren(el("p", { cls: "muted small", text: "Enviando…" }));
    $("c-test").disabled = true;
    try {
      const r = await api("POST", "/api/alerts/channels/test", b);
      box.replaceChildren(el("p", { cls: r.ok ? "ok-text" : "error-text", text: r.ok ? "✓ Mensagem de teste enviada. Confira no destino." : "✗ " + r.error }));
      if (editingC) loadChannels();
    } catch (e) {
      box.replaceChildren(el("p", { cls: "error-text", text: e.message }));
    } finally {
      $("c-test").disabled = false;
    }
  });
  $("c-delete").addEventListener("click", async () => {
    if (!editingC || !confirm(`Excluir o canal "${editingC.name}"? Ele sai de ${editingC.triggers} alerta(s).`)) return;
    try {
      await api("DELETE", `/api/alerts/channels/${editingC.id}`);
      $("c-editor").hidden = true;
      flash("Canal excluído.");
      await Promise.all([loadChannels(), loadTriggers()]);
    } catch (e) {
      showError("c-error", e.message);
    }
  });

  async function loadChannels() {
    cdata = await api("GET", "/api/alerts/channels");
    renderChannels();
  }

  (async function () {
    const me = await boot();
    if (!me) return;
    try {
      await Promise.all([loadTriggers(), loadChannels()]);
      $("main").hidden = false;
    } catch (e) {
      if (e.status === 403) { $("denied").hidden = false; return; }
      $("main").hidden = false;
      showError("list-error", e.message);
    }
  })();
})();
