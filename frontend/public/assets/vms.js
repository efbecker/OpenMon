// OpenMon - máquinas virtuais: lista com a última leitura e gráficos por período (Chart.js versionado em
// assets/vendor). Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError } = window.OpenMon;
  const STATUS = { up: ["tag-ok", "ligada"], down: ["tag-bad", "fora"], warning: ["tag-auto", "aviso"],
    unknown: ["tag-off", "desconhecida"], maintenance: ["tag-you", "manutenção"], powered_off: ["tag-off", "desligada"],
    suspended: ["tag-off", "suspensa"] };
  const ORIGIN = { vmware: "vCenter", vcloud: "vCloud", hyperv: "Hyper-V" };
  const PERIODS = [["1h", "1 hora"], ["6h", "6 horas"], ["24h", "24 horas"], ["7d", "7 dias"], ["30d", "30 dias"],
    ["90d", "90 dias"], ["365d", "1 ano"]];
  const TIER = { raw: "leituras de 1 minuto", hourly: "médias horárias", daily: "médias diárias" };
  // Duas cores por gráfico, validadas para o fundo escuro (faixa de luminosidade, daltonismo e contraste)
  const C1 = "#3a8fe8";
  const C2 = "#c97a1e";
  const ROW_LIMIT = 500;
  const params = new URLSearchParams(location.search);
  let rows = [];
  let tenants = [];
  let sortKey = "name";
  let sortDir = 1;
  let timer = null;
  let charts = [];
  let current = { id: null, period: "24h", from: null, to: null };
  let isGlobal = false;

  // ------------------------------------------------------------------ formatação
  function scaled(v, base, units, digits) {
    if (v === null || v === undefined || isNaN(v)) return "—";
    let n = Math.abs(Number(v));
    let i = 0;
    while (n >= base && i < units.length - 1) { n /= base; i += 1; }
    const d = digits !== undefined ? digits : (n >= 100 || i === 0 ? 0 : 1);
    return `${Math.sign(v) < 0 ? "-" : ""}${n.toLocaleString("pt-BR", { maximumFractionDigits: d, minimumFractionDigits: 0 })} ${units[i]}`;
  }
  const bytes = (v) => scaled(v, 1024, ["B", "KB", "MB", "GB", "TB", "PB"]);
  const bps = (v) => scaled(v, 1000, ["bps", "kbps", "Mbps", "Gbps", "Tbps"]);
  const bytesPerSec = (v) => scaled(v, 1024, ["B/s", "KB/s", "MB/s", "GB/s"]);
  const pct = (v) => (v === null || v === undefined ? "—" : `${Number(v).toLocaleString("pt-BR", { maximumFractionDigits: 1 })}%`);
  const FORMAT = { "%": pct, B: bytes, "bit/s": bps, "B/s": bytesPerSec,
    MHz: (v) => `${Math.round(v).toLocaleString("pt-BR")} MHz` };
  const fmt = (unit, v) => (FORMAT[unit] || ((x) => Number(x).toLocaleString("pt-BR", { maximumFractionDigits: 2 })))(v);

  function tag(status) {
    const [cls, label] = STATUS[status] || ["tag-off", status];
    return el("span", { cls: "tag " + cls, text: label });
  }

  function meter(v) {
    if (v === null || v === undefined) return el("span", { cls: "muted", text: "—" });
    const box = el("div", { cls: "meter", title: pct(v) });
    const fill = el("span", { cls: "meter-fill" + (v >= 90 ? " hot" : "") });
    fill.style.width = `${Math.max(0, Math.min(100, v))}%`;
    box.append(el("span", { cls: "meter-bar" }, fill), el("span", { cls: "meter-v", text: pct(v) }));
    return box;
  }

  // ------------------------------------------------------------------ frota
  const WARN = { cpu: 85, mem: 90, disk: 90 };
  const CRIT = { cpu: 95, mem: 97, disk: 97 };
  const HEALTH = { ok: ["Saudável", "h-ok"], warn: ["Atenção", "h-warn"], crit: ["Crítico", "h-crit"],
    off: ["Desligada", "h-off"], nodata: ["Sem coleta", "h-nodata"] };
  const SEV = { disaster: "Desastre", high: "Alta", average: "Média", warning: "Aviso", info: "Info" };
  let problems = [];
  let view = "cards";

  function diskPct(a) {
    const l = a.latest || {};
    if (l.fs_max_pct !== undefined) return l.fs_max_pct;
    const vols = (a.attributes || {}).volumes || [];
    if (vols.length) return Math.max(...vols.map((v) => (100 * (v.cap - v.free)) / v.cap));
    return undefined;
  }

  // Sem VMware Tools só há o disco no datastore: usado (com snapshots e swap) sobre o provisionado.
  // Pode passar de 100% e não é espaço livre dentro da VM, então não entra na saúde nem nos alertas.
  function datastorePct(a) {
    const l = a.latest || {};
    return l.disk_used !== undefined && l.disk_capacity ? (100 * l.disk_used) / l.disk_capacity : undefined;
  }

  function vmValues(a) {
    const l = a.latest || {};
    const on = a.status === "up" || a.status === "warning";
    return { on, cpu: on ? l.cpu_pct : undefined, mempct: on ? l.mem_pct : undefined, vcpu: a.attributes.vcpu || 0,
      mem: a.attributes.memory_bytes || 0, disk: diskPct(a), uptime: on ? l.uptime_s : undefined,
      net: on && (l.net_rx_bps !== undefined || l.net_tx_bps !== undefined) ? (l.net_rx_bps || 0) + (l.net_tx_bps || 0) : undefined };
  }

  // Saúde de uma VM e o motivo, na ordem: desligada, crítica, atenção, sem coleta, saudável
  function health(a) {
    const v = vmValues(a);
    const probs = problems.filter((p) => p.asset_id === a.id);
    if (!v.on) return ["off", a.status === "down" ? "VM fora do ar" : "VM desligada"];
    if (probs.some((p) => p.severity === "disaster" || p.severity === "high")) return ["crit", probs[0].message || "Problema ativo"];
    for (const [k, label] of [["disk", "Disco"], ["mem", "Memória"], ["cpu", "CPU"]]) {
      const x = k === "mem" ? v.mempct : v[k];
      if (x !== undefined && x >= CRIT[k]) return ["crit", `${label} ${pct(Math.round(x))}`];
    }
    for (const [k, label] of [["disk", "Disco"], ["mem", "Memória"], ["cpu", "CPU"]]) {
      const x = k === "mem" ? v.mempct : v[k];
      if (x !== undefined && x >= WARN[k]) return ["warn", `${label} ${pct(Math.round(x))}`];
    }
    if (probs.length || a.status === "warning") return ["warn", probs.length ? (probs[0].message || "Problema ativo") : "Alerta no virtualizador"];
    if (v.cpu === undefined && v.mempct === undefined) return ["nodata", "Sem leitura recente"];
    return ["ok", ""];
  }

  function level(x, k) {
    if (x === undefined || x === null) return "";
    return x >= CRIT[k] ? "lv-crit" : x >= WARN[k] ? "lv-warn" : "";
  }

  function osKind(a) {
    const os = String(a.os_name || (a.attributes || {}).guest_os || "").toLowerCase();
    if (os.includes("windows")) return "Windows";
    if (/linux|ubuntu|debian|centos|red hat|rhel|alma|rocky|suse|oracle/.test(os)) return "Linux";
    return os ? "Outro" : "—";
  }

  function shortOs(a) {
    const os = a.os_name || (a.attributes || {}).guest_os || "";
    return os.replace(/^Microsoft /, "").replace(/\s*\((32|64)-bit\)/, "").replace(/ Linux/, "");
  }

  function duration(s) {
    if (s === undefined || s === null) return "";
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    return d ? `${d}d ${h}h` : `${h}h ${Math.floor((s % 3600) / 60)}min`;
  }

  function filtered() {
    const st = $("filter-state").value;
    const os = $("filter-os").value;
    const list = rows.filter((a) => {
      if (os && osKind(a) !== os) return false;
      if (!st) return true;
      if (st === "attention") return ["warn", "crit"].includes(health(a)[0]);
      return (st === "on") === vmValues(a).on;
    });
    return list.sort((x, y) => {
      if (sortKey === "name") return sortDir * x.name.localeCompare(y.name, "pt-BR", { numeric: true });
      const a = vmValues(x)[sortKey];
      const b = vmValues(y)[sortKey];
      if (a === undefined && b === undefined) return 0;
      if (a === undefined) return 1;
      if (b === undefined) return -1;
      return sortDir * (a - b);
    });
  }

  function kpi(label, value, sub, cls) {
    return el("div", { cls: "kpi " + (cls || "") }, el("div", { cls: "kpi-k", text: label }),
      el("div", { cls: "kpi-v", text: value }), el("div", { cls: "kpi-s", text: sub || "" }));
  }

  function avg(list) {
    const xs = list.filter((x) => x !== undefined && x !== null);
    return xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : undefined;
  }

  function top(list, key, n) {
    return list.map((a) => [a, vmValues(a)[key]]).filter(([, x]) => x !== undefined).sort((p, q) => q[1] - p[1]).slice(0, n);
  }

  function renderHead(list, hs) {
    const tenantName = $("filter-tenant").value ? tenants.find((t) => String(t.id) === $("filter-tenant").value)?.name
      : (!isGlobal && tenants.length === 1 ? tenants[0].name : "");
    const origins = [...new Set(list.map((a) => ORIGIN[(a.attributes || {}).hypervisor]).filter(Boolean))];
    const vdcs = [...new Set(list.map((a) => (a.attributes || {}).vdc).filter(Boolean))];
    $("f-eyebrow").textContent = ["Infraestrutura de servidores", ...origins, ...vdcs.slice(0, 2)].join(" · ");
    $("f-title").replaceChildren("Servidores ", el("strong", { text: tenantName || (isGlobal ? "todos os clientes" : "") }));
    const off = hs.filter((h) => h === "off").length;
    const warn = hs.filter((h) => h === "warn").length;
    const crit = hs.filter((h) => h === "crit").length;
    const overall = crit ? "crit" : warn ? "warn" : "ok";
    const pill = $("f-health");
    pill.className = "health-pill " + HEALTH[overall][1];
    pill.replaceChildren(el("i", { cls: "dot" }), HEALTH[overall][0]);
    pill.hidden = !list.length;
    const parts = [];
    if (off) parts.push(`${off} desligada${off > 1 ? "s" : ""}`);
    if (crit) parts.push(`${crit} crítica${crit > 1 ? "s" : ""}`);
    if (warn) parts.push(`${warn} em atenção`);
    parts.push(`Atualizado em ${new Date().toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })}`);
    $("f-updated").textContent = parts.join(" · ");
  }

  function renderKpis(list, hs) {
    const on = list.filter((a) => vmValues(a).on);
    const tc = top(on, "cpu", 1)[0];
    const tm = top(on, "mempct", 1)[0];
    const td = top(list, "disk", 1)[0];
    const tn = top(on, "net", 1)[0];
    const net = on.reduce((s, a) => s + (vmValues(a).net || 0), 0);
    const open = problems.length;
    const off = hs.filter((h) => h === "off").length;
    $("kpis").replaceChildren(
      kpi("Servidores online", `${on.length} / ${list.length}`, off ? `${off} desligado${off > 1 ? "s" : ""}` : "todos ligados", off ? "k-bad" : "k-ok"),
      kpi("Problemas ativos", String(open), open ? (problems[0].asset_name || problems[0].message || "") : "Nenhum problema em aberto", open ? "k-warn" : "k-ok"),
      kpi("CPU média da frota", pct(Math.round(avg(on.map((a) => vmValues(a).cpu)) ?? NaN) || 0), tc ? `Pico: ${tc[0].name} (${pct(Math.round(tc[1]))})` : "", "k-info"),
      kpi("Memória média da frota", pct(Math.round(avg(on.map((a) => vmValues(a).mempct)) ?? NaN) || 0), tm ? `Pico: ${tm[0].name} (${pct(Math.round(tm[1]))})` : "", "k-info"),
      kpi("Disco mais ocupado", td ? pct(Math.round(td[1])) : "—", td ? td[0].name : "sem leitura de disco", td ? (td[1] >= CRIT.disk ? "k-bad" : td[1] >= WARN.disk ? "k-warn" : "k-ok") : ""),
      kpi("Tráfego de rede agora", bps(net), tn ? `Maior: ${tn[0].name}` : "", "k-info"));
  }

  function mini(label, x, k, title) {
    const bar = el("span", { cls: "mini-fill " + (k ? level(x, k) : "lv-neutral") });
    bar.style.width = `${x === undefined ? 0 : Math.max(2, Math.min(100, x))}%`;
    return el("div", { cls: "mini", attrs: title ? { title } : {} }, el("span", { cls: "mini-k", text: label }),
      el("span", { cls: "mini-v " + level(x, k), text: x === undefined ? "--" : pct(x >= 10 ? Math.round(x) : Math.round(x * 10) / 10) }),
      el("span", { cls: "mini-bar" }, bar));
  }

  function card(a) {
    const v = vmValues(a);
    const [h, why] = health(a);
    const fine = h === "ok" || h === "nodata";
    const sub = fine ? (v.uptime !== undefined ? `ligada há ${duration(v.uptime)}` : why) : why;
    const kind = osKind(a);
    const os = shortOs(a);
    const c = el("button", { cls: `vm-card ${HEALTH[h][1]}`, attrs: { type: "button", title: `${a.name}: ${HEALTH[h][0]}${why ? " · " + why : ""}${os ? " · " + os : ""}` } },
      el("div", { cls: "vm-name" }, el("i", { cls: "dot" }), el("span", { text: a.name })),
      el("div", { cls: "vm-os" }, el("span", { cls: "os-badge os-" + kind.toLowerCase().replace("—", "none"), text: kind === "—" ? "?" : kind }),
        el("span", { cls: "vm-os-name", text: os || "sistema não informado" })),
      el("div", { cls: "vm-sub" + (fine ? "" : " why"), text: sub || "" }),
      el("div", { cls: "vm-minis" }, mini("CPU", v.cpu, "cpu"), mini("MEM", v.mempct, "mem"), v.disk !== undefined ? mini("DISCO", v.disk, "disk")
        : mini("DATASTORE", datastorePct(a), null, "Disco no datastore (sem leitura dos volumes pelo VMware Tools)")));
    c.addEventListener("click", () => openDetail(a.id, true));
    return c;
  }

  function rank(id, items, k) {
    $(id).replaceChildren(...items.map(([a, x], i) => {
      const fill = el("span", { cls: "rank-fill " + (k === "mem" ? "rf-mem" : "rf-cpu") });
      fill.style.width = `${Math.max(2, Math.min(100, x))}%`;
      const li = el("li", null, el("span", { cls: "rank-i", text: String(i + 1) }),
        el("div", { cls: "rank-body" }, el("div", { cls: "rank-name", text: a.name }), el("span", { cls: "rank-bar" }, fill)),
        el("span", { cls: "rank-v " + level(x, k), text: pct(Math.round(x)) }));
      li.addEventListener("click", () => openDetail(a.id, true));
      return li;
    }));
    if (!items.length) $(id).replaceChildren(el("li", { cls: "muted small", text: "Sem leituras." }));
  }

  function renderProblems() {
    if (!problems.length) {
      $("problems").replaceChildren(el("div", { cls: "empty-ok" }, el("div", { cls: "ok-text", text: "✓ Nenhum problema em aberto" }),
        el("div", { cls: "muted small", text: "Todos os alertas das suas VMs estão normais." })));
      return;
    }
    $("problems").replaceChildren(el("ul", { cls: "prob-list" }, ...problems.slice(0, 8).map((p) => {
      const mins = Math.max(0, Math.round((Date.now() - Date.parse(p.opened_at)) / 60000));
      return el("li", null, el("span", { cls: "tag sev-" + p.severity, text: SEV[p.severity] || p.severity }),
        el("div", null, el("strong", { text: p.asset_name || "" }), el("div", { cls: "muted small", text: p.message || "" })),
        el("span", { cls: "muted small", text: mins >= 1440 ? `${Math.floor(mins / 1440)}d` : mins >= 60 ? `${Math.floor(mins / 60)}h` : `${mins} min` }));
    })));
  }

  function renderVolumes(list) {
    const vols = [];
    list.forEach((a) => ((a.attributes || {}).volumes || []).forEach((v) => vols.push({ vm: a, ...v, p: (100 * (v.cap - v.free)) / v.cap })));
    vols.sort((x, y) => y.p - x.p);
    $("vol-count").textContent = vols.length ? `(${vols.length} volumes)` : "";
    if (!vols.length) {
      $("volumes").replaceChildren(el("p", { cls: "muted small", text: "Sem dados de volumes. Eles vêm do VMware Tools pelo vCenter; " +
        "o disco provisionado de cada VM aparece nos cards e nos gráficos." }));
      return;
    }
    const shown = vols.slice(0, 7);
    $("volumes").replaceChildren(...shown.map((v) => volRow(`${v.vm.name} · ${v.path}`, v, () => openDetail(v.vm.id, true))),
      vols.length > shown.length ? el("p", { cls: "muted small center", text: `+${vols.length - shown.length} volumes abaixo` }) : "");
  }

  function volRow(label, v, onClick) {
    const p = (100 * (v.cap - v.free)) / v.cap;
    const fill = el("span", { cls: "vol-fill " + level(p, "disk") });
    fill.style.width = `${Math.min(100, p)}%`;
    const row = el("div", { cls: "vol" + (onClick ? " click" : ""), title: `${bytes(v.cap - v.free)} usados de ${bytes(v.cap)} · livre ${bytes(v.free)}` },
      el("div", { cls: "vol-head" }, el("span", { cls: "vol-name", text: label }),
        el("span", { cls: "vol-v " + level(p, "disk"), text: pct(Math.round(p)) })),
      el("div", { cls: "vol-bar" }, fill, el("i", { cls: "mark m90" }), el("i", { cls: "mark m97" })),
      el("div", { cls: "muted small", text: `${bytes(v.cap - v.free)} de ${bytes(v.cap)} · livre ${bytes(v.free)}` }));
    if (onClick) row.addEventListener("click", onClick);
    return row;
  }

  function donut(parts) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 120 120");
    svg.setAttribute("class", "donut");
    svg.setAttribute("role", "img");
    const total = parts.reduce((s, p) => s + p[1], 0) || 1;
    const r = 48;
    const len = 2 * Math.PI * r;
    let off = 0;
    parts.forEach(([, n, cls]) => {
      if (!n) return;
      const c = document.createElementNS(ns, "circle");
      c.setAttribute("cx", "60"); c.setAttribute("cy", "60"); c.setAttribute("r", String(r));
      c.setAttribute("class", "seg-" + cls);
      const seg = (n / total) * len;
      c.setAttribute("stroke-dasharray", `${Math.max(0, seg - 2)} ${len}`);
      c.setAttribute("stroke-dashoffset", String(-off));
      c.setAttribute("transform", "rotate(-90 60 60)");
      svg.append(c);
      off += seg;
    });
    svg.setAttribute("aria-label", parts.map(([l, n]) => `${l}: ${n}`).join(", "));
    return svg;
  }

  function renderOs(list) {
    const kinds = { Windows: 0, Linux: 0, Outro: 0 };
    list.forEach((a) => { const k = osKind(a); if (k in kinds) kinds[k] += 1; });
    const parts = [["Windows", kinds.Windows, "win"], ["Linux", kinds.Linux, "lin"], ["Outro", kinds.Outro, "oth"]].filter((p) => p[1]);
    const common = {};
    list.forEach((a) => { const s = shortOs(a); if (s) common[s] = (common[s] || 0) + 1; });
    const best = Object.entries(common).sort((x, y) => y[1] - x[1])[0];
    $("os-common").textContent = best ? `mais comum: ${best[0]}` : "";
    const ups = list.map((a) => [a, vmValues(a).uptime]).filter(([, u]) => u !== undefined).sort((x, y) => x[1] - y[1]);
    const rebooted = ups.filter(([, u]) => u < 86400).length;
    const center = el("div", { cls: "donut-wrap" }, donut(parts),
      el("div", { cls: "donut-c" }, el("strong", { text: String(list.length) }), el("span", { text: "servidores" })));
    const legend = el("div", { cls: "os-legend" },
      ...parts.map(([l, n, c]) => el("div", { cls: "os-row" }, el("span", null, el("i", { cls: "sw seg-bg-" + c }), l), el("strong", { text: String(n) }))),
      el("hr"),
      el("div", { cls: "os-row" }, el("span", { text: "Reiniciados em 24 h" }), el("strong", { text: String(rebooted) })),
      el("div", { cls: "os-row" }, el("span", { text: "Menor uptime" }), el("strong", { text: ups.length ? `${ups[0][0].name} · ${duration(ups[0][1])}` : "—" })),
      el("div", { cls: "os-row" }, el("span", { text: "Maior uptime" }), el("strong", { text: ups.length ? `${ups[ups.length - 1][0].name} · ${duration(ups[ups.length - 1][1])}` : "—" })));
    $("os").replaceChildren(center, legend);
  }

  function renderTable(list) {
    const shown = list.slice(0, ROW_LIMIT);
    $("table").tBodies[0].replaceChildren(...shown.map((a) => {
      const v = vmValues(a);
      const at = a.attributes || {};
      const where = [isGlobal ? ORIGIN[at.hypervisor] : "", at.vdc || (isGlobal ? at.cluster || a.parent_name : "")].filter(Boolean).join(" · ");
      const name = el("td", null, el("strong", { text: a.name }), el("div", { cls: "muted small", text: [shortOs(a), where, a.ip].filter(Boolean).join(" · ") }));
      const l = a.latest || {};
      const ds = datastorePct(a);
      const disk = v.disk !== undefined ? `volume ${pct(Math.round(v.disk))}` + (l.disk_capacity ? ` · ${bytes(l.disk_capacity)}` : "")
        : l.disk_capacity ? `${bytes(l.disk_capacity)}${ds !== undefined ? ` · datastore ${pct(Math.round(ds))}` : ""}` : "—";
      const net = v.net === undefined ? "—" : `${bps(l.net_rx_bps)} / ${bps(l.net_tx_bps)}`;
      const open = button("Gráficos", "ghost", () => openDetail(a.id, true));
      return el("tr", { cls: a.deleted_at ? "row-off" : a.status === "down" ? "row-warn" : v.on ? "" : "row-off" },
        name, el("td", { cls: "col-tenant", text: a.tenant_name }), el("td", null, tag(a.status)),
        el("td", { cls: "mono", text: v.vcpu ? String(v.vcpu) : "—" }), el("td", { cls: "mono", text: v.mem ? bytes(v.mem) : "—" }),
        el("td", null, meter(v.cpu)), el("td", null, meter(v.mempct)),
        el("td", { cls: "mono small", text: disk }), el("td", { cls: "mono small", text: net }), el("td", null, open));
    }));
    document.querySelectorAll(".col-tenant").forEach((c) => { c.hidden = tenants.length < 2; });
    document.querySelectorAll("button.sort").forEach((b) => {
      b.classList.toggle("on", b.dataset.sort === sortKey);
      b.dataset.dir = b.dataset.sort === sortKey ? (sortDir > 0 ? "↑" : "↓") : "";
    });
    return shown.length;
  }

  function render() {
    const list = filtered();
    const hs = list.map((a) => health(a)[0]);
    renderHead(list, hs);
    renderKpis(list, hs);
    const count = (h) => hs.filter((x) => x === h).length;
    const legend = [["ok", count("ok")], ["warn", count("warn")], ["crit", count("crit")], ["off", count("off")], ["nodata", count("nodata")]].filter(([, n]) => n);
    $("f-legend").replaceChildren(...legend.map(([h, n]) => el("span", { cls: "lg " + HEALTH[h][1] }, el("i", { cls: "dot" }),
      el("strong", { text: String(n) }), ` ${HEALTH[h][0].toLowerCase()}`)));
    $("f-bar").replaceChildren(...legend.map(([h, n]) => {
      const s = el("span", { cls: "hb " + HEALTH[h][1], title: `${n} ${HEALTH[h][0].toLowerCase()}` });
      s.style.flexGrow = String(n);
      return s;
    }));
    const cardsView = view === "cards";
    $("cards").hidden = !cardsView;
    $("table-box").hidden = cardsView;
    let shown = list.length;
    if (cardsView) {
      // Cards: primeiro o que precisa de atenção, depois por nome
      const order = { crit: 0, warn: 1, off: 2, nodata: 3, ok: 4 };
      const sorted = list.map((a, i) => [a, order[hs[i]]]).sort((x, y) => x[1] - y[1] || x[0].name.localeCompare(y[0].name, "pt-BR", { numeric: true }));
      const slice = sorted.slice(0, ROW_LIMIT);
      shown = slice.length;
      $("cards").replaceChildren(...slice.map(([a]) => card(a)));
    } else {
      shown = renderTable(list);
    }
    const more = list.length > shown ? ` · mostrando ${shown}, refine a busca` : "";
    $("count").textContent = `${list.length} servidor${list.length === 1 ? "" : "es"}${more}`;
    $("empty").hidden = list.length > 0;
    const on = list.filter((a) => vmValues(a).on);
    rank("top-cpu", top(on, "cpu", 5), "cpu");
    rank("top-mem", top(on, "mempct", 5), "mem");
    renderProblems();
    renderVolumes(list);
    renderOs(list);
  }

  async function load() {
    const q = new URLSearchParams({ asset_type: "vm", limit: "5000" });
    if ($("filter-tenant").value) q.set("tenant_id", $("filter-tenant").value);
    if ($("filter-q").value.trim()) q.set("q", $("filter-q").value.trim());
    try {
      const pq = new URLSearchParams({ status: "open", limit: "500" });
      if ($("filter-tenant").value) pq.set("tenant_id", $("filter-tenant").value);
      const [data, pr] = await Promise.all([api("GET", "/api/assets?" + q.toString()),
        api("GET", "/api/alerts/problems?" + pq.toString()).catch(() => ({ problems: [] }))]);
      rows = data.assets;
      tenants = data.tenants;
      const ids = new Set(rows.map((a) => a.id));
      // Volume acima de 90% e de 97% na mesma VM: fica só o mais grave (a lista já vem por severidade)
      const seen = new Set();
      problems = (pr.problems || []).filter((p) => {
        if (!ids.has(p.asset_id)) return false;
        const disk = /^Volume de disco da VM/.test(p.trigger_name || "") || /Volume mais cheio/.test(p.message || "");
        const key = `${p.asset_id}:${disk ? "disk" : p.trigger_id}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      const keep = $("filter-tenant").value;
      $("filter-tenant").replaceChildren(el("option", { text: "Todos os tenants", attrs: { value: "" } }),
        ...tenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
      $("filter-tenant").value = keep;
      $("filter-tenant").hidden = tenants.length < 2;
      if (view === "auto") view = rows.length > 300 ? "table" : "cards";
      setView(view, false);
      showError("list-error", "");
      render();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  function setView(v, rerender) {
    view = v;
    $("view-cards").classList.toggle("on", v === "cards");
    $("view-table").classList.toggle("on", v === "table");
    $("view-cards").setAttribute("aria-pressed", String(v === "cards"));
    $("view-table").setAttribute("aria-pressed", String(v === "table"));
    document.querySelector(".fleet-grid").classList.toggle("as-table", v === "table");
    try { localStorage.setItem("openmon.vms.view", v); } catch (_) { /* sem armazenamento */ }
    if (rerender) render();
  }
  $("view-cards").addEventListener("click", () => setView("cards", true));
  $("view-table").addEventListener("click", () => setView("table", true));
  try { view = localStorage.getItem("openmon.vms.view") || "auto"; } catch (_) { view = "auto"; }
  setInterval(() => { if (!$("list-card").hidden && !document.hidden) load(); }, 60000);

  // --------------------------------------------------------------- gráficos
  // Cada gráfico: um eixo só, no máximo duas séries (média e pico, ou um par do mesmo tipo de grandeza)
  const CHARTS = [
    { title: "CPU", unit: "%", series: [["cpu.usage.pct", "Média", "avg"], ["cpu.usage.pct", "Pico", "max"]], max: 100 },
    { title: "Memória", unit: "%", series: [["mem.usage.pct", "Média", "avg"], ["mem.usage.pct", "Pico", "max"]], max: 100 },
    { title: "Memória em uso", unit: "B", series: [["mem.used.bytes", "Em uso", "avg"], ["mem.allocated.bytes", "Alocada", "avg"]], onlyIfNo: "mem.usage.pct" },
    { title: "Volume mais cheio", unit: "%", series: [["fs.max.pct", "Média", "avg"], ["fs.max.pct", "Pico", "max"]], max: 100 },
    { title: "Espaço nos volumes do sistema", unit: "B", series: [["fs.used.bytes", "Em uso", "avg"], ["fs.capacity.bytes", "Tamanho", "avg"]] },
    { title: "Disco no datastore", unit: "B", series: [["disk.used.bytes", "Usado", "avg"], ["disk.capacity.bytes", "Provisionado", "avg"]] },
    { title: "Leitura e escrita em disco", unit: "B/s", series: [["disk.read.bps", "Leitura", "avg"], ["disk.write.bps", "Escrita", "avg"]] },
    { title: "IOPS", unit: "IOPS", series: [["disk.read.iops", "Leitura", "avg"], ["disk.write.iops", "Escrita", "avg"]] },
    { title: "Rede", unit: "bit/s", series: [["net.rx.bps", "Recebido", "avg"], ["net.tx.bps", "Enviado", "avg"]] },
    { title: "CPU Ready", unit: "%", series: [["cpu.ready.pct", "Média", "avg"], ["cpu.ready.pct", "Pico", "max"]] },
    { title: "Armazenamento", unit: "B", series: [["storage.used.bytes", "Usado", "avg"], ["storage.capacity.bytes", "Capacidade", "avg"]] },
  ];
  const COL = { avg: 1, min: 2, max: 3 };

  function axisTime(ms, spanMs) {
    const d = new Date(ms);
    if (spanMs <= 2 * 86400000) return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
    if (spanMs <= 120 * 86400000) return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" });
    return d.toLocaleDateString("pt-BR", { month: "short", year: "2-digit" });
  }

  function destroyCharts() {
    charts.forEach((c) => c.destroy());
    charts = [];
  }

  function makeChart(def, byKey, spanMs, from, to, showPeak) {
    let series = def.series.filter(([k]) => byKey[k]);
    if (!showPeak) series = series.filter(([, , col]) => col !== "max");
    if (!series.length || (def.onlyIfNo && byKey[def.onlyIfNo])) return null;
    const canvas = el("canvas", { attrs: { role: "img", "aria-label": `Gráfico de ${def.title}` } });
    const legend = series.length > 1 ? el("div", { cls: "chart-legend" }, ...series.map(([, label], i) =>
      el("span", { cls: "legend-item" }, el("i", { cls: "sw " + (i ? "sw2" : "sw1") }), label))) : null;
    const s0 = byKey[series[0][0]].stats;
    const box = el("div", { cls: "chart-card" },
      el("div", { cls: "chart-head" }, el("h3", { text: `${def.title}` }),
        el("span", { cls: "muted small", text: `média ${fmt(def.unit, s0.avg)} · pico ${fmt(def.unit, s0.max)}` })),
      legend, el("div", { cls: "chart-box" }, canvas));
    const datasets = series.map(([key, label, col], i) => ({
      label, data: byKey[key].points.map((p) => ({ x: p[0], y: p[COL[col]] })),
      borderColor: i ? C2 : C1, backgroundColor: i ? C2 : C1, borderWidth: 2, pointRadius: 0, pointHitRadius: 8,
      pointHoverRadius: 4, tension: 0.2, spanGaps: false, borderDash: col === "max" ? [5, 4] : [] }));
    const ink = "#94a3b8";
    const grid = "rgba(148, 163, 184, 0.12)";
    // eslint-disable-next-line no-undef
    const chart = new Chart(canvas, {
      type: "line",
      data: { datasets },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false, parsing: true, normalized: true,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            title: (items) => items.length ? new Date(items[0].parsed.x).toLocaleString("pt-BR") : "",
            label: (item) => ` ${item.dataset.label}: ${fmt(def.unit, item.parsed.y)}` } },
        },
        scales: {
          x: { type: "linear", min: from, max: to, grid: { color: grid }, border: { color: grid },
            ticks: { color: ink, maxTicksLimit: 8, callback: (v) => axisTime(v, spanMs) } },
          y: { beginAtZero: true, suggestedMax: def.max, max: def.max && s0.max <= def.max ? def.max : undefined,
            grid: { color: grid }, border: { display: false },
            ticks: { color: ink, maxTicksLimit: 6, callback: (v) => fmt(def.unit, v) } },
        },
      },
    });
    charts.push(chart);
    return box;
  }

  function stat(k, v, sub) {
    const s = el("div", { cls: "stat" }, el("div", { cls: "k", text: k }), el("div", { cls: "v", text: v }));
    if (sub) s.append(el("div", { cls: "muted small", text: sub }));
    return s;
  }

  function isoLocal(d) {
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  function renderPeriods() {
    $("periods").replaceChildren(...PERIODS.map(([k, label]) => {
      const b = el("button", { cls: "seg-btn" + (!current.from && current.period === k ? " on" : ""), text: label,
        attrs: { type: "button", "aria-pressed": String(!current.from && current.period === k) } });
      b.addEventListener("click", () => { current.period = k; current.from = null; current.to = null; loadSeries(); });
      return b;
    }));
  }

  function pushUrl() {
    const q = new URLSearchParams();
    if (current.id) q.set("id", String(current.id));
    if (current.from) { q.set("from", current.from); q.set("to", current.to); } else if (current.period !== "24h") q.set("period", current.period);
    history.replaceState(null, "", "/vms.html" + (q.toString() ? "?" + q.toString() : ""));
  }

  async function loadSeries() {
    renderPeriods();
    pushUrl();
    showError("d-error", "");
    const q = new URLSearchParams();
    if (current.from) { q.set("from", current.from); q.set("to", current.to); } else q.set("period", current.period);
    let d;
    try {
      d = await api("GET", `/api/assets/${current.id}/metrics?` + q.toString());
    } catch (e) {
      destroyCharts();
      $("charts").replaceChildren();
      showError("d-error", e.message);
      return;
    }
    const a = d.asset;
    $("d-title").textContent = a.name;
    const from = Date.parse(d.from);
    const to = Date.parse(d.to);
    $("d-sub").textContent = [a.tenant_name, (STATUS[a.status] || [0, a.status])[1],
      a.vcpu ? `${a.vcpu} vCPU` : "", a.memory_bytes ? `${bytes(a.memory_bytes)} de RAM` : ""].filter(Boolean).join(" · ");
    $("d-tier").textContent = `${new Date(from).toLocaleString("pt-BR")} até ${new Date(to).toLocaleString("pt-BR")} · ` +
      `${TIER[d.tier] || d.tier}, um ponto a cada ${d.bucket_seconds >= 86400 ? `${d.bucket_seconds / 86400} dia(s)` :
        d.bucket_seconds >= 3600 ? `${d.bucket_seconds / 3600} h` : `${d.bucket_seconds / 60} min`}`;
    const byKey = {};
    d.series.forEach((s) => { byKey[s.key] = s; });
    const st = (key, label, unit) => {
      const s = byKey[key];
      return s ? stat(label, fmt(unit, s.stats.avg), `pico ${fmt(unit, s.stats.max)}`) : null;
    };
    const growth = (key, label) => {
      const s = byKey[key];
      if (!s) return null;
      const diff = s.stats.last - s.stats.first;
      return stat(label, bytes(s.stats.last), `${diff >= 0 ? "+" : "−"}${bytes(Math.abs(diff))} no período`);
    };
    $("d-stats").replaceChildren(...[st("cpu.usage.pct", "CPU média", "%"), st("mem.usage.pct", "Memória média", "%"),
      st("fs.max.pct", "Volume mais cheio", "%"),
      growth("fs.used.bytes", "Volumes em uso") || growth("disk.used.bytes", "Disco usado")
        || growth("disk.capacity.bytes", "Disco provisionado"),
      growth("storage.used.bytes", "Armazenamento usado"),
      st("net.rx.bps", "Rede recebida", "bit/s"), st("net.tx.bps", "Rede enviada", "bit/s")].filter(Boolean));
    destroyCharts();
    const showPeak = d.bucket_seconds > 60;
    const boxes = CHARTS.map((def) => makeChart(def, byKey, to - from, from, to, showPeak)).filter(Boolean);
    $("charts").replaceChildren(...boxes);
    $("d-empty").hidden = d.series.length > 0;
    loadVolumes(current.id);
  }

  async function loadVolumes(id) {
    let vols = [];
    try {
      vols = ((await api("GET", `/api/assets/${id}`)).asset.attributes || {}).volumes || [];
    } catch (_) { vols = []; }
    if (current.id !== id) return;
    $("d-volumes").replaceChildren(...vols.map((v) => volRow(v.path, v)));
    $("d-volumes-box").hidden = !vols.length;
  }

  function openDetail(id, scroll) {
    current = { id, period: current.period || "24h", from: null, to: null };
    $("detail").hidden = false;
    $("list-card").hidden = true;
    const now = new Date();
    $("p-to").value = isoLocal(now);
    $("p-from").value = isoLocal(new Date(now.getTime() - 7 * 86400000));
    loadSeries();
    if (scroll) window.scrollTo({ top: 0, behavior: "smooth" });
  }

  $("btn-custom").addEventListener("click", () => {
    const f = new Date($("p-from").value);
    const t = new Date($("p-to").value);
    if (isNaN(f) || isNaN(t) || f >= t) { showError("d-error", "Escolha um início antes do fim."); return; }
    current.from = f.toISOString();
    current.to = t.toISOString();
    loadSeries();
  });
  $("btn-close").addEventListener("click", () => {
    destroyCharts();
    $("detail").hidden = true;
    $("list-card").hidden = false;
    current.id = null;
    pushUrl();
    if (!rows.length) load();
  });
  document.querySelectorAll("button.sort").forEach((b) => b.addEventListener("click", () => {
    const k = b.dataset.sort;
    if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = k === "name" ? 1 : -1; }
    render();
  }));
  $("filter-tenant").addEventListener("change", load);
  $("filter-state").addEventListener("change", render);
  $("filter-os").addEventListener("change", render);
  $("filter-q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 300); });

  (async function () {
    const me = await boot();
    if (!me) return;
    isGlobal = me.user.scope === "global";
    $("main").hidden = false;
    const id = Number(params.get("id"));
    if (id > 0) {
      if (params.get("from") && params.get("to")) {
        current = { id, period: "24h", from: params.get("from"), to: params.get("to") };
        $("detail").hidden = false;
        $("list-card").hidden = true;
        loadSeries();
      } else {
        current.period = PERIODS.some(([k]) => k === params.get("period")) ? params.get("period") : "24h";
        openDetail(id, false);
      }
      return;
    }
    load();
  })();
})();
