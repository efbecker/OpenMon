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
      el("td", null, el("strong", { text: v.name }), v.new_in_period && dateField === "created_at" ? el("span", { cls: "tag tag-ok ml", text: "nova" }) : null),
      el("td", { cls: "small", text: v.os || "—", title: v.os || "" }),
      el("td", { cls: "mono", text: C.num(v.vcpu, 0) }),
      el("td", { cls: "mono", text: mem(v.memory_bytes) }),
      el("td", { cls: "mono", text: tb(v.disk_bytes) }),
      dateField === "created_at" ? el("td", null, el("span", { cls: "tag " + (on ? "tag-ok" : "tag-off"), text: on ? "Ligada" : "Desligada" })) : null);
  }

  function renderGrowth(g, o) {
    show(["g-evo", "g-years", "g-vms"], true);
    show(["c-usage", "c-top"], false);
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
    show(["g-evo", "g-years", "g-vms", "g-removed"], false);
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
      if (kind === "growth") renderGrowth(data, o); else renderConsumption(data, o);
      $("print").disabled = false;
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

  function csv() {
    const L = state.last;
    if (!L) return;
    const rows = [];
    const d = L.data;
    if (L.kind === "growth") {
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
    a.download = `${L.kind === "growth" ? "crescimento" : "consumo"}-${(d.tenant.slug || d.tenant.id)}-${iso(new Date())}.csv`;
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
    if (q.get("kind")) $("kind").value = q.get("kind") === "consumption" ? "consumption" : "growth";
    if (q.get("start") || q.get("end")) { $("start").value = q.get("start") || ""; $("end").value = q.get("end") || ""; }
    else preset($("kind").value === "growth" ? "all" : "30");
    $("kind").addEventListener("change", () => preset($("kind").value === "growth" ? "all" : "30"));
    document.querySelectorAll("[data-preset]").forEach((b) => b.addEventListener("click", () => { preset(b.getAttribute("data-preset")); generate(); }));
    $("form").addEventListener("submit", (ev) => { ev.preventDefault(); generate(); });
    $("print").addEventListener("click", () => window.print());
    $("csv").addEventListener("click", csv);
    $("main").hidden = false;
    if (!tid) { showError("error", "Nenhum cliente disponível para o seu usuário."); return; }
    generate();
  })();
})();
