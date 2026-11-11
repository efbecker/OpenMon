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

  // ------------------------------------------------------------------ lista
  function vmValues(a) {
    const l = a.latest || {};
    const on = a.status === "up" || a.status === "warning";
    return { on, cpu: on ? l.cpu_pct : undefined, mempct: on ? l.mem_pct : undefined, vcpu: a.attributes.vcpu || 0,
      mem: a.attributes.memory_bytes || 0, disk: l.disk_used !== undefined ? l.disk_used : l.disk_capacity,
      net: on && (l.net_rx_bps !== undefined || l.net_tx_bps !== undefined) ? (l.net_rx_bps || 0) + (l.net_tx_bps || 0) : undefined };
  }

  function filtered() {
    const st = $("filter-state").value;
    const list = rows.filter((a) => !st || (st === "on") === vmValues(a).on);
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

  function renderSummary(list) {
    const on = list.filter((a) => vmValues(a).on);
    const sum = (f) => list.reduce((acc, a) => acc + (f(a) || 0), 0);
    const tiles = [["VMs", String(list.length)], ["Ligadas", String(on.length)],
      ["vCPU alocadas", sum((a) => a.attributes.vcpu).toLocaleString("pt-BR")],
      ["Memória alocada", bytes(sum((a) => a.attributes.memory_bytes))],
      ["Disco usado", bytes(sum((a) => (a.latest || {}).disk_used))],
      ["Disco provisionado", bytes(sum((a) => (a.latest || {}).disk_capacity))]];
    $("summary").replaceChildren(...tiles.map(([k, v]) => el("div", { cls: "stat" }, el("div", { cls: "k", text: k }),
      el("div", { cls: "v", text: v }))));
  }

  function render() {
    const list = filtered();
    renderSummary(list);
    const shown = list.slice(0, ROW_LIMIT);
    $("table").tBodies[0].replaceChildren(...shown.map((a) => {
      const v = vmValues(a);
      const at = a.attributes || {};
      const where = [ORIGIN[at.hypervisor] || a.integration_name, at.vdc || at.cluster || a.parent_name].filter(Boolean).join(" · ");
      const name = el("td", null, el("strong", { text: a.name }), el("div", { cls: "muted small", text: [where, a.ip].filter(Boolean).join(" · ") }));
      const l = a.latest || {};
      const disk = l.disk_capacity ? `${bytes(l.disk_used)} de ${bytes(l.disk_capacity)}` : bytes(l.disk_used);
      const net = v.net === undefined ? "—" : `${bps(l.net_rx_bps)} / ${bps(l.net_tx_bps)}`;
      const open = button("Gráficos", "ghost", () => openDetail(a.id, true));
      return el("tr", { cls: a.deleted_at ? "row-off" : a.status === "down" ? "row-warn" : v.on ? "" : "row-off" },
        name, el("td", { cls: "col-tenant", text: a.tenant_name }), el("td", null, tag(a.status)),
        el("td", { cls: "mono", text: v.vcpu ? String(v.vcpu) : "—" }), el("td", { cls: "mono", text: v.mem ? bytes(v.mem) : "—" }),
        el("td", null, meter(v.cpu)), el("td", null, meter(v.mempct)),
        el("td", { cls: "mono small", text: disk }), el("td", { cls: "mono small", text: net }), el("td", null, open));
    }));
    const more = list.length > shown.length ? ` · mostrando ${shown.length}, refine a busca` : "";
    $("count").textContent = `(${list.length}${more})`;
    $("empty").hidden = list.length > 0;
    document.querySelectorAll(".col-tenant").forEach((c) => { c.hidden = tenants.length < 2; });
    document.querySelectorAll("button.sort").forEach((b) => {
      b.classList.toggle("on", b.dataset.sort === sortKey);
      b.dataset.dir = b.dataset.sort === sortKey ? (sortDir > 0 ? "↑" : "↓") : "";
    });
  }

  async function load() {
    const q = new URLSearchParams({ asset_type: "vm", limit: "5000" });
    if ($("filter-tenant").value) q.set("tenant_id", $("filter-tenant").value);
    if ($("filter-q").value.trim()) q.set("q", $("filter-q").value.trim());
    try {
      const data = await api("GET", "/api/assets?" + q.toString());
      rows = data.assets;
      tenants = data.tenants;
      const keep = $("filter-tenant").value;
      $("filter-tenant").replaceChildren(el("option", { text: "Todos os tenants", attrs: { value: "" } }),
        ...tenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
      $("filter-tenant").value = keep;
      $("filter-tenant").hidden = tenants.length < 2;
      showError("list-error", "");
      render();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  // --------------------------------------------------------------- gráficos
  // Cada gráfico: um eixo só, no máximo duas séries (média e pico, ou um par do mesmo tipo de grandeza)
  const CHARTS = [
    { title: "CPU", unit: "%", series: [["cpu.usage.pct", "Média", "avg"], ["cpu.usage.pct", "Pico", "max"]], max: 100 },
    { title: "Memória", unit: "%", series: [["mem.usage.pct", "Média", "avg"], ["mem.usage.pct", "Pico", "max"]], max: 100 },
    { title: "Memória em uso", unit: "B", series: [["mem.used.bytes", "Em uso", "avg"], ["mem.allocated.bytes", "Alocada", "avg"]], onlyIfNo: "mem.usage.pct" },
    { title: "Disco", unit: "B", series: [["disk.used.bytes", "Usado", "avg"], ["disk.capacity.bytes", "Provisionado", "avg"]] },
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
      growth("disk.used.bytes", "Disco usado") || growth("disk.capacity.bytes", "Disco provisionado"),
      growth("storage.used.bytes", "Armazenamento usado"),
      st("net.rx.bps", "Rede recebida", "bit/s"), st("net.tx.bps", "Rede enviada", "bit/s")].filter(Boolean));
    destroyCharts();
    const showPeak = d.bucket_seconds > 60;
    const boxes = CHARTS.map((def) => makeChart(def, byKey, to - from, from, to, showPeak)).filter(Boolean);
    $("charts").replaceChildren(...boxes);
    $("d-empty").hidden = d.series.length > 0;
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
  $("filter-q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 300); });

  (async function () {
    const me = await boot();
    if (!me) return;
    isGlobal = me.user.scope === "global";
    if (!isGlobal) $("intro").textContent = "Suas máquinas virtuais com a última leitura de CPU, memória, disco e rede. Abra uma VM para ver os gráficos por período.";
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
