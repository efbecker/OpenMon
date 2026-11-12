// OpenMon - inventário de ativos e interfaces. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const TYPE = { vcenter: "vCenter", datacenter: "Datacenter", cluster: "Cluster", hypervisor_host: "Host",
    vm: "VM", datastore: "Datastore", network_switch: "Switch", router: "Roteador", firewall: "Firewall",
    storage: "Storage", physical_server: "Servidor físico", backup_server: "Servidor de backup",
    backup_repository: "Repositório de backup", other: "Outro" };
  // ifAdminStatus / ifOperStatus (IF-MIB)
  const OPER = { 1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "ausente", 7: "down (camada inferior)" };
  const STATUS = { up: ["tag-ok", "no ar"], down: ["tag-bad", "fora"], warning: ["tag-auto", "aviso"],
    unknown: ["tag-off", "desconhecido"], maintenance: ["tag-you", "manutenção"], powered_off: ["tag-off", "desligada"],
    suspended: ["tag-off", "suspensa"] };
  // Tipos com séries de CPU/memória/disco/rede ou armazenamento: abrem os gráficos por período (vms.html)
  const CHARTS = new Set(["vm", "hypervisor_host", "datacenter", "datastore", "backup_repository"]);
  const params = new URLSearchParams(location.search);
  let data = { assets: [], tenants: [], summary: {}, can_manage: false };
  let detail = null;
  let timer = null;

  function bps(v) {
    if (v === null || v === undefined) return "—";
    const u = ["bps", "kbps", "Mbps", "Gbps", "Tbps"];
    let i = 0;
    let n = Number(v);
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i += 1; }
    return `${n >= 100 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${u[i]}`;
  }

  function bytes(v) {
    if (v === null || v === undefined) return "—";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0;
    let n = Number(v);
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  function duration(s) {
    if (!s && s !== 0) return "—";
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    return d ? `${d} d ${h} h` : `${h} h ${Math.floor((s % 3600) / 60)} min`;
  }

  function tag(status) {
    const [cls, label] = STATUS[status] || ["tag-off", status];
    return el("span", { cls: "tag " + cls, text: label });
  }

  function reading(a) {
    const l = a.latest || {};
    const parts = [];
    if (l.cpu_pct !== undefined) parts.push(`CPU ${l.cpu_pct.toFixed(0)}%`);
    if (l.mem_pct !== undefined) parts.push(`mem ${l.mem_pct.toFixed(0)}%`);
    if (l.net_rx_bps !== undefined || l.net_tx_bps !== undefined) parts.push(`↓${bps(l.net_rx_bps)} ↑${bps(l.net_tx_bps)}`);
    if (l.storage_capacity) parts.push(`${(100 * (1 - (l.storage_free || 0) / l.storage_capacity)).toFixed(0)}% usado`);
    if (!parts.length && l.uptime_s !== undefined) parts.push(`no ar há ${duration(l.uptime_s)}`);
    return parts.join(" · ") || "—";
  }

  // ------------------------------------------------------------------ lista
  function renderSummary() {
    const s = data.summary;
    const tiles = Object.keys(s).sort((a, b) => (TYPE[a] || a).localeCompare(TYPE[b] || b)).map((t) => {
      const total = Object.values(s[t]).reduce((x, y) => x + y, 0);
      const down = s[t].down || 0;
      const v = el("div", { cls: "v", text: String(total) });
      if (down) v.append(el("span", { cls: "bad small", text: ` · ${down} fora` }));
      const tile = el("button", { cls: "stat stat-btn" + ($("filter-type").value === t ? " on" : ""), attrs: { type: "button" } },
        el("div", { cls: "k", text: TYPE[t] || t }), v);
      tile.addEventListener("click", () => { $("filter-type").value = $("filter-type").value === t ? "" : t; load(); });
      return tile;
    });
    $("summary").replaceChildren(...tiles);
    $("summary").hidden = !tiles.length;
  }

  function render() {
    $("table").tBodies[0].replaceChildren(...data.assets.map((a) => {
      const name = el("td", null, el("strong", { text: a.name }));
      if (a.parent_name) name.append(el("div", { cls: "muted small", text: a.parent_name }));
      const tenant = el("td", null, a.tenant_name);
      if (a.tenant_locked) tenant.append(el("span", { cls: "muted small", text: " · fixo", title: "Tenant fixado manualmente" }));
      const tr = el("tr", { cls: a.deleted_at ? "row-off" : a.status === "down" ? "row-warn" : "" },
        name, el("td", { text: TYPE[a.asset_type] || a.asset_type }), tenant,
        el("td", { cls: "mono small", text: a.ip || a.hostname || "—" }),
        el("td", { cls: "small", text: (a.asset_type === "vm" && a.attributes.guest_os) || [a.vendor, a.model].filter(Boolean).join(" ") || "—" }),
        el("td", null, a.deleted_at ? el("span", { cls: "tag tag-off", text: "removido" }) : tag(a.status)),
        el("td", { cls: "small", text: reading(a) }), el("td", { text: a.interfaces ? String(a.interfaces) : "—" }),
        el("td", { cls: "small", text: when(a.last_seen_at, "nunca") }),
        el("td", null, CHARTS.has(a.asset_type) && !a.deleted_at
          ? el("a", { cls: "btn small-btn ghost", text: "Gráficos", attrs: { href: `/vms.html?id=${a.id}` } }) : null,
        button("Abrir", "ghost", () => openDetail(a.id))));
      return tr;
    }));
    $("count").textContent = data.assets.length ? `(${data.assets.length})` : "";
    const hasLinks = (data.links || []).length > 0;
    $("empty").hidden = data.assets.length > 0 || hasLinks;
    $("table").parentElement.hidden = !data.assets.length && hasLinks;
  }

  function renderLinks() {
    const links = data.links || [];
    $("links").tBodies[0].replaceChildren(...links.map((f) => {
      const peak = Math.max(f.in_bps || 0, f.out_bps || 0);
      const use = f.contracted_bps && f.sample_at ? Math.round((100 * peak) / f.contracted_bps) : null;
      const act = el("td");
      if (f.asset_name) act.append(button("Abrir", "ghost", () => openDetail(f.asset_id)));
      return el("tr", { cls: use !== null && use >= 90 ? "row-warn" : "" }, el("td", { text: f.tenant_name }),
        el("td", { text: f.asset_name || "—" }), el("td", { cls: "mono", text: f.if_name || "—" }),
        el("td", { cls: "small", text: f.if_alias || "" }), el("td", { text: f.contracted_bps ? bps(f.contracted_bps) : "—" }),
        el("td", { cls: "mono small", text: bps(f.in_bps) }), el("td", { cls: "mono small", text: bps(f.out_bps) }),
        el("td", { cls: use !== null && use >= 90 ? "bad" : "", text: use === null ? "—" : `${use}%` }),
        el("td", null, el("span", { cls: "tag " + (f.oper_status === 1 ? "tag-ok" : "tag-bad"), text: OPER[f.oper_status] || "—" })), act);
    }));
    $("links-count").textContent = links.length ? `(${links.length})` : "";
    $("links-card").hidden = !links.length;
  }

  function fillTenantSelect(sel, keep, firstLabel) {
    const cur = keep !== undefined ? keep : sel.value;
    const opts = data.tenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } }));
    if (firstLabel) opts.unshift(el("option", { text: firstLabel, attrs: { value: "" } }));
    sel.replaceChildren(...opts);
    sel.value = cur === null || cur === undefined ? "" : String(cur);
  }

  async function load() {
    const q = new URLSearchParams();
    if ($("filter-tenant").value) q.set("tenant_id", $("filter-tenant").value);
    if ($("filter-type").value) q.set("asset_type", $("filter-type").value);
    if ($("filter-q").value.trim()) q.set("q", $("filter-q").value.trim());
    if (params.get("integration")) q.set("integration_id", params.get("integration"));
    try {
      data = await api("GET", "/api/assets?" + q.toString());
      showError("list-error", "");
      fillTenantSelect($("filter-tenant"), $("filter-tenant").value, "Todos os tenants");
      $("filter-tenant").hidden = data.tenants.length < 2;
      renderSummary();
      render();
      renderLinks();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  // --------------------------------------------------------------- detalhe
  function stat(k, v) {
    return el("div", { cls: "stat" }, el("div", { cls: "k", text: k }), el("div", { cls: "v", text: v }));
  }

  function ifRow(f, manage) {
    const cells = [el("td", { cls: "mono small", text: String(f.if_index) }), el("td", { cls: "mono", text: f.if_name || "—" }),
      el("td", { cls: "small", text: f.if_alias || f.if_descr || "", title: f.if_descr || "" }),
      el("td", { text: f.speed_bps ? bps(f.speed_bps) : "—" }),
      el("td", null, el("span", { cls: "tag " + (f.oper_status === 1 ? "tag-ok" : f.admin_status === 2 ? "tag-off" : "tag-bad"),
        text: f.admin_status === 2 ? "desligada" : (OPER[f.oper_status] || "—") })),
      el("td", { cls: "mono small", text: f.is_monitored ? bps(f.in_bps) : "—" }),
      el("td", { cls: "mono small", text: f.is_monitored ? bps(f.out_bps) : "—" })];
    if (!manage) {
      cells.push(el("td", { text: f.is_monitored ? "sim" : "não" }), el("td", { text: f.is_customer_link ? "sim" : "—" }),
        el("td", { text: f.tenant_name }), el("td", { text: f.contracted_bps ? String(f.contracted_bps / 1e6) : "—" }), el("td"));
      return el("tr", { cls: f.is_monitored ? "" : "row-off" }, ...cells);
    }
    const mon = el("input", { attrs: { type: "checkbox", "aria-label": "Monitorar" } });
    mon.checked = f.is_monitored;
    const link = el("input", { attrs: { type: "checkbox", "aria-label": "Link de cliente" } });
    link.checked = f.is_customer_link;
    const ten = el("select", { attrs: { "aria-label": "Tenant da interface" } });
    fillTenantSelect(ten, f.tenant_id);
    const mbps = el("input", { cls: "num", attrs: { type: "number", min: "0", step: "any", "aria-label": "Banda contratada em Mbps" } });
    mbps.value = f.contracted_bps ? String(f.contracted_bps / 1e6) : "";
    const save = button("Salvar", "ghost", async () => {
      save.disabled = true;
      showError("d-error", "");
      const body = { is_monitored: mon.checked, is_customer_link: link.checked, tenant_id: Number(ten.value),
        contracted_bps: Number(mbps.value) > 0 ? Math.round(Number(mbps.value) * 1e6) : null };
      try {
        await api("PUT", `/api/admin/interfaces/${f.id}`, body);
        Object.assign(f, body);
        save.textContent = "Salvo ✓";
        load();
        tr.classList.toggle("row-off", !body.is_monitored);
      } catch (e) {
        showError("d-error", `${f.if_name}: ${e.message}`);
        save.disabled = false;
      }
    });
    save.disabled = true;
    const dirty = () => { save.disabled = false; save.textContent = "Salvar"; };
    const syncLink = () => {
      ten.disabled = !link.checked;
      mbps.disabled = !link.checked;
      if (link.checked) mon.checked = true;
      if (!link.checked) ten.value = String(detail.asset.tenant_id);
    };
    link.addEventListener("change", () => { syncLink(); dirty(); });
    [mon, ten, mbps].forEach((n) => n.addEventListener("change", dirty));
    mbps.addEventListener("input", dirty);
    ten.disabled = !link.checked;
    mbps.disabled = !link.checked;
    cells.push(el("td", null, mon), el("td", null, link), el("td", null, ten), el("td", null, mbps), el("td", null, save));
    const tr = el("tr", { cls: f.is_monitored ? "" : "row-off" }, ...cells);
    tr.match = (q, only) => (!only || mon.checked) && (!q || [f.if_name, f.if_alias, f.if_descr].join(" ").toLowerCase().includes(q));
    return tr;
  }

  function renderIfs() {
    const q = $("if-q").value.trim().toLowerCase();
    const only = $("if-only").checked;
    const rows = detail.rows;
    rows.forEach((r) => { r.hidden = r.match ? !r.match(q, only) : false; });
    const mon = detail.interfaces.filter((f) => f.is_monitored).length;
    $("d-if-count").textContent = `(${detail.interfaces.length} · ${mon} monitorada${mon === 1 ? "" : "s"})`;
  }

  async function openDetail(id) {
    showError("d-error", "");
    $("d-ok").hidden = true;
    let d;
    try {
      d = await api("GET", `/api/assets/${id}`);
    } catch (e) {
      showError("list-error", e.message);
      return;
    }
    detail = d;
    const a = d.asset;
    const at = a.attributes || {};
    const l = a.latest || {};
    $("d-title").textContent = a.name;
    $("d-sub").textContent = [TYPE[a.asset_type] || a.asset_type, a.integration_name ? `via ${a.integration_name}` : "",
      a.ip || a.hostname || ""].filter(Boolean).join(" · ");
    const stats = [stat("Situação", (STATUS[a.status] || [0, a.status])[1]), stat("Tenant", a.tenant_name)];
    if (a.vendor || a.model) stats.push(stat("Fabricante / modelo", [a.vendor, a.model].filter(Boolean).join(" ")));
    if (a.os_name || at.guest_os) stats.push(stat("Sistema", a.os_name || at.guest_os));
    if (at.sys_descr) stats.push(stat("sysDescr", at.sys_descr));
    if (at.location) stats.push(stat("Local", at.location));
    if (at.vcpu) stats.push(stat("vCPU", String(at.vcpu)));
    if (at.memory_bytes) stats.push(stat("Memória", bytes(at.memory_bytes)));
    if (l.cpu_pct !== undefined) stats.push(stat("CPU", `${l.cpu_pct.toFixed(1)}%`));
    if (l.mem_pct !== undefined) stats.push(stat("Memória usada", `${l.mem_pct.toFixed(1)}%`));
    if (l.uptime_s !== undefined) stats.push(stat("No ar há", duration(l.uptime_s)));
    if (l.storage_capacity) stats.push(stat("Capacidade", `${bytes(l.storage_capacity)} · livre ${bytes(l.storage_free)}`));
    if (a.children) stats.push(stat("Itens abaixo", String(a.children)));
    stats.push(stat("Visto em", when(a.last_seen_at, "nunca")), stat("Descoberto em", when(a.first_seen_at)));
    $("d-stats").replaceChildren(...stats);

    $("d-manage").hidden = !d.can_manage;
    if (d.can_manage) {
      fillTenantSelect($("d-tenant"), a.tenant_id);
      $("d-locked").checked = true;
    }
    $("if-help").hidden = !d.can_manage;
    detail.rows = d.interfaces.map((f) => ifRow(f, d.can_manage));
    $("ifs").tBodies[0].replaceChildren(...detail.rows);
    $("d-ifs-box").hidden = d.interfaces.length === 0;
    $("if-q").value = "";
    $("if-only").checked = d.interfaces.length > 40 && d.interfaces.some((f) => f.is_monitored);
    if (d.interfaces.length) renderIfs();
    $("detail").hidden = false;
    $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  $("btn-asset-save").addEventListener("click", async () => {
    if (!detail) return;
    showError("d-error", "");
    const body = { tenant_id: Number($("d-tenant").value), tenant_locked: $("d-locked").checked, is_monitored: true };
    try {
      await api("PUT", `/api/admin/assets/${detail.asset.id}`, body);
      $("d-ok").textContent = "Tenant do ativo salvo.";
      $("d-ok").hidden = false;
      await load();
      await openDetail(detail.asset.id);
      $("d-ok").hidden = false;
    } catch (e) {
      showError("d-error", e.message);
    }
  });

  $("btn-close").addEventListener("click", () => { $("detail").hidden = true; detail = null; });
  $("if-q").addEventListener("input", () => detail && renderIfs());
  $("if-only").addEventListener("change", () => detail && renderIfs());
  $("filter-tenant").addEventListener("change", load);
  $("filter-type").addEventListener("change", load);
  $("filter-q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 300); });
  Object.entries(TYPE).forEach(([k, v]) => $("filter-type").append(el("option", { text: v, attrs: { value: k } })));

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.scope !== "global") {
      $("links-title").textContent = "Seus links";
      $("links-intro").textContent = "Portas do datacenter que atendem você, com a banda contratada e o tráfego dos últimos minutos.";
    }
    if (params.get("integration")) {
      $("filter-note").hidden = false;
      $("filter-note").replaceChildren("Mostrando os ativos de uma integração · ", el("a", { text: "ver todos", attrs: { href: "/inventario.html" } }));
    }
    $("main").hidden = false;
    load();
  })();
})();
