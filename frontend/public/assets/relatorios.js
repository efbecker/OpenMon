// OpenMon - relatórios por período: crescimento de recursos e consumo x contratado. Sem innerHTML (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, showError } = window.OpenMon;
  const C = window.OpenMon.charts;
  const state = { scope: null, last: null };
  const GBn = 1024 ** 3;

  const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const day = (s) => (s ? new Date(s).toLocaleDateString("pt-BR") : "—");
  const tb = (b) => (b >= 1024 ** 4 ? `${C.num(b / 1024 ** 4, 1)} TB` : `${C.num(b / GBn, 0)} GB`);
  const mem = (b) => `${C.num(b / GBn, 0)} GB`;

  function preset(p) {
    const now = new Date();
    let s = null;
    let e = now;
    if (p === "month") { s = new Date(now.getFullYear(), now.getMonth() - 1, 1); e = new Date(now.getFullYear(), now.getMonth(), 0); }
    else if (p === "year") s = new Date(now.getFullYear(), 0, 1);
    else if (p !== "all") s = new Date(now.getTime() - Number(p) * 86400000);
    $("start").value = s ? iso(s) : "";
    $("end").value = iso(e);
  }

  function kpi(label, value, change, sinceLabel, startText) {
    const up = change && change.delta > 0;
    const down = change && change.delta < 0;
    return el("div", { cls: "rep-kpi" },
      el("div", { cls: "k", text: label }),
      el("div", { cls: "big", text: value }),
      change ? el("div", { cls: "small " + (up ? "good" : down ? "bad" : "muted") },
        el("span", { text: up ? "▲ " : down ? "▼ " : "" }),
        el("span", { text: change.pct === null ? (change.delta ? "novo" : "sem variação") : `${C.signed(change.pct, (v) => C.num(v, 1))}%` }),
        el("span", { cls: "muted", text: ` desde ${sinceLabel} (${startText})` })) : null);
  }

  function meta(items) {
    $("r-meta").replaceChildren(...items.map(([k, v]) => el("div", null, el("span", { cls: "muted", text: k }), el("b", { text: v }))));
  }

  function show(ids, on) { ids.forEach((id) => { $(id).hidden = !on; }); }

  function envTable(o) {
    $("env").hidden = !o.vdcs.length;
    const cell = (used, cap, pct) => el("td", null, el("div", { text: cap ? `${used} de ${cap}` : used }),
      el("div", { cls: "muted small", text: pct === null || pct === undefined ? "" : C.pct(pct) }));
    $("env-table").tBodies[0].replaceChildren(...o.vdcs.map((d) => el("tr", null,
      el("td", null, el("strong", { text: d.vdc })),
      cell(C.ghz(d.cpu.used_mhz), d.cpu.allocated_mhz ? C.ghz(d.cpu.allocated_mhz) : null, d.cpu.pct),
      cell(mem(d.memory.used_bytes || 0), d.memory.allocated_bytes ? mem(d.memory.allocated_bytes) : null, d.memory.pct),
      cell(tb(d.storage.used_bytes || 0), d.storage.limit_bytes ? tb(d.storage.limit_bytes) : null, d.storage.pct),
      el("td", { cls: "mono", text: `${d.vms_on} de ${d.vms}` }))));
  }

  function vmRow(v, dateField) {
    const on = v.status === "up";
    return el("tr", null,
      el("td", { cls: "mono", text: day(v[dateField]), title: v.created_estimated && dateField === "created_at" ? "Data em que o OpenMon viu a VM pela primeira vez" : "" }),
      el("td", null, el("strong", { text: v.name }), v.is_new && dateField === "created_at" ? el("span", { cls: "tag tag-ok ml", text: "nova", attrs: { title: "Criada nos últimos 7 dias" } }) : null),
      el("td", { cls: "small", text: v.os || "—", title: v.os || "" }),
      el("td", { cls: "mono", text: C.num(v.vcpu, 0) }),
      el("td", { cls: "mono", text: mem(v.memory_bytes) }),
      el("td", { cls: "mono", text: tb(v.disk_bytes) }),
      dateField === "created_at" ? el("td", null, el("span", { cls: "tag " + (on ? "tag-ok" : "tag-off"), text: on ? "Ligada" : "Desligada" })) : null);
  }

  function renderGrowth(g, o) {
    show(["g-evo", "g-years", "g-vms"], true);
    show(["c-usage", "c-top", "f-sum", "f-vms"], false);
    $("r-kind").textContent = "Relatório de crescimento de recursos";
    const since = g.kpis_since || (g.labels.length ? g.labels[0] : "");
    const k = g.kpis;
    $("r-kpis").replaceChildren(
      kpi("Máquinas virtuais", C.num(k.vms.end, 0), k.vms, since, C.num(k.vms.start, 0)),
      kpi("vCPU", C.num(k.vcpu.end, 0), k.vcpu, since, C.num(k.vcpu.start, 0)),
      kpi("Memória", mem(k.memory_bytes.end), k.memory_bytes, since, mem(k.memory_bytes.start)),
      kpi("Disco", tb(k.disk_bytes.end), k.disk_bytes, since, tb(k.disk_bytes.start)));
    const s = g.series;
    const opt = { stepped: true, xTicks: 6 };
    C.line($("g0"), g.labels, [{ label: "Máquinas virtuais", data: s.vms }], { ...opt, fmt: (v) => C.num(v, 0) });
    C.line($("g1"), g.labels, [{ label: "vCPU", data: s.vcpu }], { ...opt, fmt: (v) => C.num(v, 0) });
    C.line($("g2"), g.labels, [{ label: "Memória (GB)", data: s.memory_bytes.map((v) => v / GBn) }], { ...opt, fmt: (v) => C.num(v, 0) });
    C.line($("g3"), g.labels, [{ label: "Disco (GB)", data: s.disk_bytes.map((v) => v / GBn) }], { ...opt, fmt: (v) => C.num(v, 0) });
    const add = (v, f) => el("span", { cls: v > 0 ? "good small" : "muted small", text: ` ${C.signed(v, f)}` });
    $("years").tBodies[0].replaceChildren(...g.years.map((y) => el("tr", null,
      el("td", null, el("strong", { text: String(y.year) }), y.partial_until ? el("span", { cls: "muted small", text: ` até ${y.partial_until}` }) : null),
      el("td", null, el("span", { text: C.num(y.vms, 0) }), add(y.added.vms, (v) => C.num(v, 0))),
      el("td", null, el("span", { text: C.num(y.vcpu, 0) }), add(y.added.vcpu, (v) => C.num(v, 0))),
      el("td", null, el("span", { text: mem(y.memory_bytes) }), add(y.added.memory_bytes, mem)),
      el("td", null, el("span", { text: tb(y.disk_bytes) }), add(y.added.disk_bytes, tb)))));
    envTable(o);
    $("vm-count").textContent = `(${g.vms.length})`;
    $("vms").tBodies[0].replaceChildren(...g.vms.map((v) => vmRow(v, "created_at")));
    $("g-removed").hidden = !g.removed.length;
    $("rm-count").textContent = `(${g.removed.length})`;
    $("removed").tBodies[0].replaceChildren(...g.removed.map((v) => vmRow(v, "deleted_at")));
    $("r-foot").textContent = "Totais reconstruídos pela data de criação e de remoção de cada VM, com o tamanho atual de cada uma."
      + (g.estimated_dates ? ` ${g.estimated_dates} VM(s) sem data de criação no hypervisor usam a data em que o OpenMon as viu pela primeira vez.` : "");
  }

  function renderConsumption(c, o) {
    show(["g-evo", "g-years", "g-vms", "g-removed", "f-sum", "f-vms"], false);
    show(["c-usage"], true);
    $("r-kind").textContent = "Relatório de consumo x contratado";
    const k = o.contract;
    const cpu = c.cpu && c.cpu.pct_stats;
    const memS = c.memory && c.memory.pct_stats;
    $("r-kpis").replaceChildren(
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "CPU média" }), el("div", { cls: "big", text: C.pct(cpu && cpu.avg) }),
        el("div", { cls: "muted small", text: `pico ${C.pct(cpu && cpu.max)} · contratado ${C.ghz(c.cpu && c.cpu.allocated_last)}` })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "Memória média" }), el("div", { cls: "big", text: C.pct(memS && memS.avg) }),
        el("div", { cls: "muted small", text: `pico ${C.pct(memS && memS.max)} · contratada ${mem((c.memory && c.memory.allocated_last) || 0)}` })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "Armazenamento" }), el("div", { cls: "big", text: c.storage ? tb(c.storage.stats.last) : "—" }),
        el("div", { cls: "muted small", text: c.storage && c.storage.allocated_last ? `de ${tb(c.storage.allocated_last)} · ${C.pct(c.storage.pct_stats && c.storage.pct_stats.last)}` : "sem limite" })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "VMs" }), el("div", { cls: "big", text: C.num(o.totals.vms, 0) }),
        el("div", { cls: "muted small", text: `${o.totals.vms_on} ligadas · ${C.num(o.totals.vcpu, 0)} vCPU` })));
    const labels = c.labels.map((x) => C.timeLabel(x, c.step_seconds));
    const tier = { samples: "leituras de cada coleta", hourly: "médias por hora", daily: "médias por dia" }[c.tier] || "";
    $("c-sub").textContent = `${tier}. A linha tracejada é o contratado.` + (k ? "" : " Este cliente não tem data center virtual (vCloud).");
    if (c.cpu) C.line($("c0"), labels, [{ label: "Em uso", data: c.cpu.pct || [] },
      { label: "Contratado", data: (c.cpu.pct || []).map((v) => (v === null ? null : 100)), kind: "limit" }], { fmt: (v) => C.pct(v), suggestedMax: 100 });
    const g = (a) => (a || []).map((v) => (v === null ? null : v / GBn));
    if (c.memory) C.line($("c1"), labels, [{ label: "Em uso", data: g(c.memory.used) },
      { label: "Contratada", data: g(c.memory.allocated), kind: "limit" }], { fmt: (v) => `${C.num(v, 0)} GB` });
    const t = (a) => (a || []).map((v) => (v === null ? null : v / 1024 ** 4));
    if (c.storage) {
      const ser = [{ label: "Em uso", data: t(c.storage.used) }];
      if (c.storage.allocated) ser.push({ label: "Limite", data: t(c.storage.allocated), kind: "limit" });
      C.line($("c2"), labels, ser, { fmt: (v) => `${C.num(v, 1)} TB` });
    }
    const hours = (h) => (h === null || h === undefined ? "—" : h >= 48 ? `${C.num(h / 24, 1)} dias` : `${C.num(h, 0)} h`);
    const row = (name, b, cap, f) => (b ? el("tr", null, el("td", null, el("strong", { text: name })), el("td", { cls: "mono", text: cap }),
      el("td", { cls: "mono", text: `${f(b.stats.avg)}${b.pct_stats ? ` · ${C.pct(b.pct_stats.avg)}` : ""}` }),
      el("td", { cls: "mono", text: `${f(b.stats.max)}${b.pct_stats ? ` · ${C.pct(b.pct_stats.max)}` : ""}` }),
      el("td", { cls: "mono", text: `${f(b.stats.p95)}${b.pct_stats ? ` · ${C.pct(b.pct_stats.p95)}` : ""}` }),
      el("td", { cls: "mono", text: hours(b.hours_above_90) })) : null);
    $("c-table").tBodies[0].replaceChildren(...[
      row("CPU", c.cpu, C.ghz(c.cpu && c.cpu.allocated_last), C.ghz),
      row("Memória", c.memory, mem((c.memory && c.memory.allocated_last) || 0), mem),
      row("Armazenamento", c.storage, c.storage && c.storage.allocated_last ? tb(c.storage.allocated_last) : "sem limite", tb)].filter(Boolean));
    const top = c.top_vms || { cpu: [], memory: [] };
    $("c-top").hidden = !top.cpu.length && !top.memory.length;
    const rows = (list) => list.map((v) => el("tr", null, el("td", { text: v.name }),
      el("td", { cls: "mono", text: C.pct(v.avg, 1) }), el("td", { cls: "mono", text: C.pct(v.peak, 1) })));
    $("top-cpu").tBodies[0].replaceChildren(...rows(top.cpu));
    $("top-mem").tBodies[0].replaceChildren(...rows(top.memory));
    envTable(o);
    $("r-foot").textContent = "Contratado = alocação do data center virtual no vCloud Director. Percentil 95: 95% do tempo o uso ficou abaixo deste valor.";
  }

  async function generate() {
    showError("error", "");
    const tenant = $("tenant").value;
    const kind = $("kind").value;
    const p = new URLSearchParams({ tenant_id: tenant });
    if ($("start").value) p.set("start", $("start").value);
    if ($("end").value) p.set("end", $("end").value);
    $("go").disabled = true;
    try {
      const [data, o] = await Promise.all([api("GET", `/api/reports/${kind}?${p}`), api("GET", `/api/reports/overview?tenant_id=${tenant}`)]);
      state.last = { kind, data, overview: o };
      $("report").hidden = false;
      $("r-tenant").textContent = data.tenant.name;
      const endDay = new Date(new Date(data.end).getTime() - 1);
      meta([["Período", `${day(data.start)} a ${endDay.toLocaleDateString("pt-BR")}`],
        ["Ambiente", o.vdcs.map((d) => d.vdc).join(", ") || "—"], ["Emitido em", new Date().toLocaleDateString("pt-BR")]]);
      if (kind === "growth") renderGrowth(data, o);
      else if (kind === "finops") renderFinops(data, o);
      else renderConsumption(data, o);
      $("print").disabled = false;
      $("html").disabled = false;
      $("csv").disabled = false;
      const u = new URLSearchParams({ tenant, kind });
      if ($("start").value) u.set("start", $("start").value);
      if ($("end").value) u.set("end", $("end").value);
      history.replaceState(null, "", `?${u}`);
    } catch (e) {
      showError("error", e.message);
    } finally {
      $("go").disabled = false;
    }
  }

  const KIND_FILE = { growth: "crescimento", consumption: "consumo", finops: "finops" };
  const STATUS = { ok: ["Adequada", "ok"], warn: ["Pode economizar", "warn"], crit: ["Precisa de mais recursos", "crit"],
    nodata: ["Sem métricas", "nodata"] };
  const PRICE = "openmon.finops.prices";

  function prices() {
    const n = (id) => { const v = parseFloat(String($(id).value).replace(",", ".")); return isFinite(v) && v > 0 ? v : 0; };
    return { vcpu: n("p-vcpu"), mem: n("p-mem"), disk: n("p-disk") };
  }

  function money(v) { return v.toLocaleString("pt-BR", { style: "currency", currency: "BRL" }); }
  function ghz(mhz) { return mhz === null || mhz === undefined ? "—" : `${C.num(mhz / 1000, 1)} GHz`; }
  function rate(b) {
    if (b === null || b === undefined) return "—";
    return b >= 1e6 ? `${C.num(b / 1e6, 1)} Mbps` : `${C.num(b / 1e3, 0)} kbps`;
  }
  function uptime(sec) {
    if (!sec) return "—";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    return d ? `${d} dia(s)${h ? `, ${h}h` : ""}` : `${h}h`;
  }
  function osIcon(os) {
    const t = (os || "").toLowerCase();
    return t.includes("windows") ? "🪟 " : /linux|ubuntu|debian|centos|alma|rocky|red hat|suse|oracle/.test(t) ? "🐧 " : "💻 ";
  }

  function renderFinops(f, o) {
    show(["g-evo", "g-years", "g-vms", "g-removed", "c-usage", "c-top"], false);
    show(["f-sum", "f-vms"], true);
    $("env").hidden = true;
    $("r-kind").textContent = "Relatório FinOps · dimensionamento das VMs";
    const t = f.totals;
    const pr = prices();
    const savingR = t.saving.vcpu * pr.vcpu + t.saving.memory_gb * pr.mem + t.saving.disk_gb * pr.disk;
    const extraR = t.extra.vcpu * pr.vcpu + t.extra.memory_gb * pr.mem;
    const analysed = f.vms.length - t.status.nodata;
    const kpis = [
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "VMs analisadas" }), el("div", { cls: "big", text: `${analysed}` }),
        el("div", { cls: "muted small", text: `${t.status.ok} adequadas · ${t.status.warn} com sobra · ${t.status.crit} sob pressão` })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "vCPU liberáveis" }), el("div", { cls: "big", text: C.num(t.saving.vcpu, 0) }),
        el("div", { cls: "muted small", text: `de ${C.num(t.allocated.vcpu, 0)} alocadas` })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: "Memória liberável" }), el("div", { cls: "big", text: `${C.num(t.saving.memory_gb, 0)} GB` }),
        el("div", { cls: "muted small", text: `de ${C.num(t.allocated.memory_gb, 0)} GB alocados` })),
      el("div", { cls: "rep-kpi" }, el("div", { cls: "k", text: savingR ? "Economia estimada" : "Disco liberável" }),
        el("div", { cls: "big", text: savingR ? money(savingR) : `${C.num(t.saving.disk_gb, 0)} GB` }),
        el("div", { cls: "muted small", text: savingR ? "por mês, com os preços informados" : "provisionado sem uso" }))];
    $("r-kpis").replaceChildren(...kpis);

    const parts = [];
    parts.push(`Foram analisadas ${analysed} VM(s) com métricas no período`
      + (t.status.nodata ? ` (${t.status.nodata} sem leituras de uso ficaram de fora)` : "") + ". ");
    if (t.status.warn) parts.push(`${t.status.warn} têm recursos sobrando: dá para liberar ${C.num(t.saving.vcpu, 0)} vCPU, `
      + `${C.num(t.saving.memory_gb, 0)} GB de memória e ${C.num(t.saving.disk_gb, 0)} GB de disco`
      + (savingR ? `, cerca de ${money(savingR)} por mês. ` : ". "));
    if (t.status.crit) parts.push(`${t.status.crit} estão sob pressão e precisam de mais ${C.num(t.extra.vcpu, 0)} vCPU e `
      + `${C.num(t.extra.memory_gb, 0)} GB de memória` + (extraR ? ` (cerca de ${money(extraR)} por mês)` : "") + ". ");
    if (!t.status.warn && !t.status.crit && analysed) parts.push("Todas estão bem dimensionadas para o uso medido. ");
    parts.push(`Critério: P95 do uso abaixo de ${f.thresholds.cpu_low}% (CPU) ou ${f.thresholds.mem_low}% (memória) indica sobra; `
      + `acima de ${f.thresholds.cpu_high}% / ${f.thresholds.mem_high}% indica pressão. As recomendações miram ${f.thresholds.target}% de uso.`);
    $("f-text").replaceChildren(el("strong", { text: "Resumo: " }), el("span", { text: parts.join("") }));

    const avgLine = (v) => {
      const a = v.avg;
      const bits = [];
      if (a.cpu_pct !== null) bits.push(`CPU ${C.pct(a.cpu_pct)}${a.cpu_mhz ? ` (${ghz(a.cpu_mhz)})` : ""}`);
      if (a.mem_pct !== null) bits.push(`RAM ${C.pct(a.mem_pct)}${v.memory_bytes ? ` (${C.num(a.mem_pct * v.memory_bytes / 100 / GBn, 1)} GB)` : ""}`);
      if (v.volumes && v.volumes.length) bits.push(`Disco ${v.volumes.map((x) => C.pct(x.pct)).join(" | ")}`);
      else if (a.disk_used_bytes && a.disk_capacity_bytes) bits.push(`Disco ${C.pct(a.disk_used_bytes / a.disk_capacity_bytes * 100)}`);
      if (a.net_rx_bps !== null || a.net_tx_bps !== null) bits.push(`Rede ↓${rate(a.net_rx_bps)} ↑${rate(a.net_tx_bps)}`);
      return bits.join(" · ") || "—";
    };
    $("f-table").tBodies[0].replaceChildren(...f.vms.map((v) => {
      const main = v.recs[0];
      const link = el("a", { text: v.name, attrs: { href: `#vm-${v.id}` } });
      return el("tr", null,
        el("td", null, el("span", { cls: `dot ${v.status}`, title: STATUS[v.status][0] })),
        el("td", null, el("strong", null, link)),
        el("td", { cls: "small", text: osIcon(v.os) + (v.os || "não informado") }),
        el("td", { cls: "mono small", text: avgLine(v) }),
        el("td", { cls: "rec-short" }, el("span", { cls: main.level, text: v.recs.map((r) => r.title).join(" · ") })));
    }));

    const labels = f.labels.map((x) => C.timeLabel(x, f.step_seconds));
    const tier = { samples: "leituras de cada coleta", hourly: "médias por hora", daily: "médias por dia" }[f.tier] || "";
    $("f-sub").textContent = `Alocado, médias de consumo e recomendação de cada VM, com o uso de CPU e memória no período (${tier}).`;
    const cards = [];
    const charts = [];
    f.vms.forEach((v) => {
      const a = v.avg;
      const cap = a.cpu_capacity_mhz;
      const h = el("h3", null, el("span", { cls: `dot ${v.status}` }), el("span", { text: v.name }),
        el("span", { cls: "tag tag-tenant", text: osIcon(v.os) + (v.os || "SO não informado") }),
        cap ? el("span", { cls: "tag tag-you", text: `⚡ ${ghz(cap)}` }) : null);
      const alloc = el("div", { cls: "vm-box" }, el("div", { cls: "k", text: "Alocado" }),
        el("div", null, "vCPU: ", el("b", { text: v.vcpu ? C.num(v.vcpu, 0) : "—" })),
        cap ? el("div", null, "Capacidade: ", el("b", { text: ghz(cap) })) : null,
        el("div", null, "Memória: ", el("b", { text: v.memory_bytes ? `${C.num(v.memory_bytes / GBn, 0)} GB` : "—" })),
        el("div", null, "Disco: ", el("b", { text: a.disk_capacity_bytes ? tb(a.disk_capacity_bytes) : "—" })));
      const use = el("div", { cls: "vm-box" }, el("div", { cls: "k", text: "Médias de consumo" }),
        el("div", null, "CPU: ", el("b", { text: a.cpu_pct === null ? "—" : `${C.pct(a.cpu_pct)}${a.cpu_mhz ? ` · ${ghz(a.cpu_mhz)}` : ""} (pico ${C.pct(a.cpu_peak)})` })),
        el("div", null, "Memória: ", el("b", { text: a.mem_pct === null ? "—" : `${v.memory_bytes ? `${C.num(a.mem_pct * v.memory_bytes / 100 / GBn, 1)} GB · ` : ""}${C.pct(a.mem_pct)} (pico ${C.pct(a.mem_peak)})` })),
        el("div", null, "Discos: ", el("b", { text: v.volumes && v.volumes.length ? v.volumes.map((x) => `${x.path || ""} ${C.pct(x.pct)}`.trim()).join(" | ")
          : a.disk_used_bytes && a.disk_capacity_bytes ? `${tb(a.disk_used_bytes)} de ${tb(a.disk_capacity_bytes)}` : "—" })),
        el("div", null, "Rede: ", el("b", { text: a.net_rx_bps === null && a.net_tx_bps === null ? "—" : `↓${rate(a.net_rx_bps)} ↑${rate(a.net_tx_bps)}` })),
        a.uptime_s ? el("div", null, "Uptime: ", el("b", { text: uptime(a.uptime_s) })) : null);
      const icon = { crit: "🚨 ", warn: "🔻 ", ok: "✅ ", info: "ℹ️ " };
      const ana = el("div", { cls: "vm-box" }, el("div", { cls: "k", text: "Análise de capacidade e FinOps" }),
        el("ul", { cls: "recs" }, ...v.recs.map((r) => el("li", { cls: r.level }, el("strong", { text: (icon[r.level] || "") + r.title + ": " }), el("span", { text: r.text })))));
      const card = el("div", { cls: "vm-card", attrs: { id: `vm-${v.id}` } }, h, el("div", { cls: "vm-boxes" }, alloc, use, ana));
      if (v.series) {
        const cv = el("canvas", { attrs: { role: "img", "aria-label": `CPU e memória de ${v.name}` } });
        card.append(el("div", { cls: "chart-box" }, cv));
        charts.push([cv, v.series]);
      }
      cards.push(card);
    });
    $("f-cards").replaceChildren(...cards);
    charts.forEach(([cv, sr]) => C.line(cv, labels, [{ label: "CPU", data: sr.cpu, kind: "used", fill: false },
      { label: "Memória", data: sr.mem, kind: "second", fill: false }], { fmt: (x) => C.pct(x), suggestedMax: 100 }));
    $("r-foot").textContent = "Sobra e pressão medidas pelo percentil 95 das médias do período (picos isolados não contam). "
      + "Reduzir vCPU e memória exige reiniciar a VM; reduzir disco exige migrar os dados. Valide com o responsável pela aplicação antes de aplicar.";
  }

  function fileName(ext) {
    const L = state.last;
    const t = L.data.tenant;
    return `${KIND_FILE[L.kind] || L.kind}-${t.slug || t.id}-${iso(new Date())}.${ext}`;
  }

  function download(blob, name) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  async function dataUrl(src) {
    try {
      const r = await fetch(src, { credentials: "same-origin" });
      const b = await r.blob();
      return await new Promise((ok) => { const f = new FileReader(); f.onload = () => ok(f.result); f.readAsDataURL(b); });
    } catch (_) { return src; }
  }

  // Gráfico como imagem nítida (2x) para o arquivo HTML
  function chartImage(canvas) {
    const ch = window.Chart && window.Chart.getChart(canvas);
    if (!ch) return canvas.toDataURL("image/png");
    const old = ch.options.devicePixelRatio;
    ch.options.devicePixelRatio = 2;
    ch.resize();
    const url = canvas.toDataURL("image/png");
    ch.options.devicePixelRatio = old;
    ch.resize();
    return url;
  }

  // Relatório em HTML: um arquivo só (estilo, logo e gráficos embutidos), abre offline em qualquer navegador
  async function htmlExport() {
    const L = state.last;
    if (!L) return;
    $("html").disabled = true;
    try {
      const src = $("report");
      const clone = src.cloneNode(true);
      clone.hidden = false;
      clone.querySelectorAll("[hidden]").forEach((n) => n.remove());
      const live = src.querySelectorAll("canvas");
      clone.querySelectorAll("canvas").forEach((c, i) => {
        const img = document.createElement("img");
        img.src = chartImage(live[i]);
        img.alt = c.getAttribute("aria-label") || "";
        img.className = "chart-img";
        c.replaceWith(img);
      });
      for (const img of clone.querySelectorAll("img:not(.chart-img)")) {
        img.src = await dataUrl(img.getAttribute("src"));
      }
      let css = "";
      try { css = await (await fetch("assets/openmon.css", { credentials: "same-origin" })).text(); } catch (_) { /* sem estilo */ }
      css += "\n.chart-img { display: block; width: 100%; height: 100%; object-fit: contain; }"
        + "\nbody { padding: 24px 0; } .rep-gen { margin-top: 8px; }";
      const title = `${$("r-kind").textContent} · ${L.data.tenant.name}`;
      const esc = (t) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
      const doc = "<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n"
        + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        + `<title>${esc(title)}</title>\n<style>\n${css}\n</style>\n</head>\n<body>\n`
        + `<main class="page wide">\n${clone.outerHTML}\n<p class="muted small rep-gen">Gerado pelo OpenMon em ${esc(new Date().toLocaleString("pt-BR"))}.</p>\n</main>\n</body>\n</html>\n`;
      download(new Blob([doc], { type: "text/html;charset=utf-8" }), fileName("html"));
    } catch (e) {
      showError("error", `Não foi possível gerar o HTML: ${e.message}`);
    } finally {
      $("html").disabled = false;
    }
  }

  function csv() {
    const L = state.last;
    if (!L) return;
    const rows = [];
    const d = L.data;
    if (L.kind === "finops") {
      rows.push(["Situação", "Máquina virtual", "Sistema operacional", "vCPU", "vCPU recomendadas", "Memória (GB)",
        "Memória recomendada (GB)", "CPU média (%)", "CPU P95 (%)", "CPU pico (%)", "Memória média (%)", "Memória P95 (%)",
        "Disco (GB)", "Disco usado (GB)", "vCPU liberáveis", "RAM liberável (GB)", "Disco liberável (GB)", "Recomendações"]);
      d.vms.forEach((v) => {
        const r = (k) => v.recs.find((x) => x.kind === k);
        const cpu = r("cpu_down") || r("cpu_up");
        const memR = r("mem_down") || r("mem_up");
        const g = (b) => (b === null || b === undefined ? "" : (b / GBn).toFixed(0));
        const f = (x) => (x === null || x === undefined ? "" : Number(x).toFixed(1));
        rows.push([STATUS[v.status][0], v.name, v.os || "", v.vcpu || "", cpu ? cpu.to : "", g(v.memory_bytes), memR ? memR.to : "",
          f(v.avg.cpu_pct), f(v.avg.cpu_p95), f(v.avg.cpu_peak), f(v.avg.mem_pct), f(v.avg.mem_p95),
          g(v.avg.disk_capacity_bytes), g(v.avg.disk_used_bytes), v.saving.vcpu, f(v.saving.memory_gb), f(v.saving.disk_gb),
          v.recs.map((x) => x.title).join(" | ")]);
      });
    } else if (L.kind === "growth") {
      rows.push(["Mês", "Máquinas virtuais", "vCPU", "Memória (GB)", "Disco (GB)"]);
      d.labels.forEach((m, i) => rows.push([m, d.series.vms[i], d.series.vcpu[i],
        (d.series.memory_bytes[i] / GBn).toFixed(0), (d.series.disk_bytes[i] / GBn).toFixed(0)]));
      rows.push([]);
      rows.push(["Criada em", "Máquina virtual", "Sistema operacional", "vCPU", "Memória (GB)", "Disco (GB)", "Estado", "Removida em"]);
      d.vms.concat(d.removed).forEach((v) => rows.push([day(v.created_at), v.name, v.os || "", v.vcpu,
        (v.memory_bytes / GBn).toFixed(0), (v.disk_bytes / GBn).toFixed(0), v.status === "up" ? "Ligada" : "Desligada", v.deleted_at ? day(v.deleted_at) : ""]));
    } else {
      rows.push(["Data/hora", "CPU em uso (MHz)", "CPU contratada (MHz)", "CPU (%)", "Memória em uso (GB)", "Memória contratada (GB)",
        "Armazenamento em uso (GB)", "Armazenamento limite (GB)"]);
      const at = (b, k, i, div) => (b && b[k] && b[k][i] !== null && b[k][i] !== undefined ? (div ? (b[k][i] / div).toFixed(1) : b[k][i]) : "");
      d.labels.forEach((t, i) => rows.push([new Date(t).toLocaleString("pt-BR"), at(d.cpu, "used", i), at(d.cpu, "allocated", i),
        at(d.cpu, "pct", i), at(d.memory, "used", i, GBn), at(d.memory, "allocated", i, GBn), at(d.storage, "used", i, GBn), at(d.storage, "allocated", i, GBn)]));
    }
    const text = "﻿" + rows.map((r) => r.map((x) => {
      const raw = String(x === null || x === undefined ? "" : x);
      const s = /^-?\d+\.\d+$/.test(raw) ? raw.replace(".", ",") : raw;  // decimal com vírgula (Excel pt-BR)
      return /[;"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(";")).join("\r\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
    a.download = fileName("csv");
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  (async function () {
    const me = await boot();
    if (!me) return;
    try {
      state.scope = await api("GET", "/api/reports/scope");
    } catch (e) {
      $("main").hidden = false;
      showError("error", e.message);
      return;
    }
    const q = new URLSearchParams(location.search);
    const want = Number(q.get("tenant")) || null;
    const sel = $("tenant");
    sel.replaceChildren(...state.scope.tenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
    const tid = state.scope.tenants.some((t) => t.id === want) ? want : state.scope.default_tenant_id;
    if (tid) sel.value = String(tid);
    if (q.get("kind")) $("kind").value = ["consumption", "finops"].includes(q.get("kind")) ? q.get("kind") : "growth";
    try {
      const saved = JSON.parse(localStorage.getItem(PRICE) || "{}");
      $("p-vcpu").value = saved.vcpu || ""; $("p-mem").value = saved.mem || ""; $("p-disk").value = saved.disk || "";
    } catch (_) { /* navegação privada */ }
    ["p-vcpu", "p-mem", "p-disk"].forEach((id) => $(id).addEventListener("change", () => {
      try { localStorage.setItem(PRICE, JSON.stringify(prices())); } catch (_) { /* sem armazenamento */ }
      if (state.last && state.last.kind === "finops") renderFinops(state.last.data, state.last.overview);
    }));
    const kindUi = () => { $("prices").hidden = $("kind").value !== "finops"; };
    kindUi();
    $("kind").addEventListener("change", kindUi);
    if (q.get("start") || q.get("end")) { $("start").value = q.get("start") || ""; $("end").value = q.get("end") || ""; }
    else preset($("kind").value === "growth" ? "all" : "30");
    $("kind").addEventListener("change", () => preset($("kind").value === "growth" ? "all" : "30"));
    document.querySelectorAll("[data-preset]").forEach((b) => b.addEventListener("click", () => { preset(b.getAttribute("data-preset")); generate(); }));
    $("form").addEventListener("submit", (ev) => { ev.preventDefault(); generate(); });
    $("print").addEventListener("click", () => window.print());
    $("csv").addEventListener("click", csv);
    $("html").addEventListener("click", htmlExport);
    $("main").hidden = false;
    if (!tid) { showError("error", "Nenhum cliente disponível para o seu usuário."); return; }
    generate();
  })();
})();
