// OpenMon - painel do cliente: contratado x em uso, consumo no período e VMs. Sem innerHTML (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, showError } = window.OpenMon;
  const C = window.OpenMon.charts;
  const state = { tenant: null, days: 30, overview: null };

  function stat(k, v, sub) {
    return el("div", { cls: "stat" }, el("div", { cls: "k", text: k }), el("div", { cls: "v", text: v }),
      sub ? el("div", { cls: "muted small", text: sub }) : null);
  }

  function level(p) { return p === null || p === undefined ? "" : p >= 95 ? "crit" : p >= 85 ? "high" : ""; }

  function meter(label, pct, used, cap, note) {
    const bar = el("progress", { attrs: { max: "100", value: String(Math.min(100, pct || 0)) } });
    bar.className = "meter-bar " + level(pct);
    return el("div", { cls: "meter " + level(pct) },
      el("div", { cls: "k", text: label }),
      el("div", { cls: "meter-v" }, el("span", { cls: "big", text: C.pct(pct) }),
        el("span", { cls: "muted small", text: pct >= 95 ? " no limite" : pct >= 85 ? " perto do limite" : "" })),
      bar,
      el("div", { cls: "muted small", text: cap ? `${used} de ${cap}` : `${used} · sem limite` }),
      note ? el("div", { cls: "muted tiny", text: note }) : null);
  }

  function renderOverview(o) {
    state.overview = o;
    $("title").textContent = `Painel de consumo · ${o.tenant.name}`;
    const k = o.contract;
    $("no-vdc").hidden = !!k;
    $("meters").hidden = !k;
    if (k) {
      $("meters").replaceChildren(
        meter("CPU", k.cpu.pct, C.ghz(k.cpu.used_mhz), k.cpu.allocated_mhz ? C.ghz(k.cpu.allocated_mhz) : null),
        meter("Memória", k.memory.pct, C.bytes(k.memory.used_bytes), k.memory.allocated_bytes ? C.bytes(k.memory.allocated_bytes) : null),
        meter("Armazenamento", k.storage.pct, C.bytes(k.storage.used_bytes), k.storage.limit_bytes ? C.bytes(k.storage.limit_bytes) : null));
    }
    const t = o.totals;
    $("totals").replaceChildren(
      stat("VMs ligadas", `${t.vms_on} de ${t.vms}`),
      stat("vCPU alocadas", C.num(t.vcpu, 0)),
      stat("Memória das VMs", C.bytes(t.memory_bytes)),
      stat("Disco das VMs", C.bytes(t.disk_bytes)),
      stat("Atualizado", new Date(o.generated_at).toLocaleString("pt-BR")));

    $("vdc-card").hidden = !o.vdcs.length;
    const rows = [];
    o.vdcs.forEach((d) => {
      const cell = (pct, used, cap) => el("td", null, el("div", { text: cap ? `${used} de ${cap}` : used }),
        el("div", { cls: "muted small", text: pct === null || pct === undefined ? "" : C.pct(pct, 1) }));
      rows.push(el("tr", null,
        el("td", null, el("strong", { text: d.vdc }), el("div", { cls: "muted small", text: [d.org, d.allocation_model].filter(Boolean).join(" · ") })),
        cell(d.cpu.pct, C.ghz(d.cpu.used_mhz), d.cpu.allocated_mhz ? C.ghz(d.cpu.allocated_mhz) : null),
        cell(d.memory.pct, C.bytes(d.memory.used_bytes), d.memory.allocated_bytes ? C.bytes(d.memory.allocated_bytes) : null),
        cell(d.storage.pct, C.bytes(d.storage.used_bytes), d.storage.limit_bytes ? C.bytes(d.storage.limit_bytes) : null),
        el("td", { cls: "mono", text: `${d.vms_on} de ${d.vms}` })));
      d.storage_profiles.forEach((p) => rows.push(el("tr", { cls: "sub-row" },
        el("td", { text: `Perfil ${p.name}${p.default ? " (padrão)" : ""}` }), el("td"), el("td"),
        el("td", null, el("div", { text: p.limit_bytes ? `${C.bytes(p.used_bytes)} de ${C.bytes(p.limit_bytes)}` : `${C.bytes(p.used_bytes)} · sem limite` }),
          el("div", { cls: "muted small", text: p.pct === null ? "" : C.pct(p.pct, 1) })),
        el("td"))));
    });
    $("vdcs").tBodies[0].replaceChildren(...rows);
    renderVms();
  }

  function renderVms() {
    const o = state.overview;
    if (!o) return;
    const q = $("vm-q").value.trim().toLowerCase();
    const list = o.vms.filter((v) => !q || v.name.toLowerCase().includes(q) || (v.os || "").toLowerCase().includes(q));
    $("vm-count").textContent = `(${o.vms.length})`;
    $("vm-empty").hidden = list.length > 0;
    const shown = state.allVms ? list : list.slice(0, 100);
    $("vm-more").hidden = shown.length === list.length;
    $("vm-more").textContent = `Mostrar todas as ${list.length}`;
    $("vms").tBodies[0].replaceChildren(...shown.map((v) => {
      const on = v.status === "up";
      return el("tr", null,
        el("td", null, el("strong", { text: v.name })),
        el("td", { cls: "small", text: v.os || "—", title: v.os || "" }),
        el("td", { cls: "mono", text: C.num(v.vcpu, 0) }),
        el("td", { cls: "mono", text: C.bytes(v.memory_bytes) }),
        el("td", { cls: "mono", text: C.bytes(v.disk_bytes) }),
        el("td", { cls: "mono", text: C.pct(v.cpu_pct) }),
        el("td", { cls: "mono", text: C.pct(v.mem_pct) }),
        el("td", { cls: "mono", text: new Date(v.created_at).toLocaleDateString("pt-BR"),
          title: v.created_estimated ? "Data em que o OpenMon viu a VM pela primeira vez" : "" }),
        el("td", null, el("span", { cls: "tag " + (on ? "tag-ok" : "tag-off"), text: on ? "Ligada" : "Desligada" })));
    }));
  }

  function statLine(box, items) {
    $(box).replaceChildren(...items.map(([k, v]) => el("span", null, el("span", { cls: "muted", text: `${k} ` }), el("strong", { text: v }))));
  }

  function renderUsage(c) {
    const labels = c.labels.map((x) => C.timeLabel(x, c.step_seconds));
    const any = c.cpu || c.memory || c.storage;
    $("usage-card").hidden = !state.overview || !state.overview.contract;
    $("usage-empty").hidden = !!any;
    document.querySelectorAll(".chart-panel").forEach((f) => { f.hidden = !any; });
    const from = new Date(c.start).toLocaleString("pt-BR");
    const tier = { samples: "leituras de cada coleta", hourly: "médias por hora", daily: "médias por dia" }[c.tier] || "";
    $("usage-sub").textContent = `De ${from} até agora · ${tier}. A linha tracejada é o contratado.`;
    if (c.cpu) {
      C.line($("ch-cpu"), labels, [{ label: "Em uso", data: c.cpu.pct || [], kind: "used" },
        { label: "Contratado", data: (c.cpu.pct || []).map((v) => (v === null ? null : 100)), kind: "limit" }],
      { fmt: (v) => C.pct(v), suggestedMax: 100 });
      const s = c.cpu.pct_stats || {};
      statLine("st-cpu", [["Média", C.pct(s.avg)], ["Pico", C.pct(s.max)], ["P95", C.pct(s.p95)],
        ["Contratado", C.ghz(c.cpu.allocated_last)]]);
    }
    if (c.memory) {
      const g = (a) => (a || []).map((v) => (v === null ? null : v / 1024 ** 3));
      C.line($("ch-mem"), labels, [{ label: "Em uso", data: g(c.memory.used), kind: "used" },
        { label: "Contratada", data: g(c.memory.allocated), kind: "limit" }], { fmt: (v) => `${C.num(v, 0)} GB` });
      const s = c.memory.stats;
      statLine("st-mem", [["Média", C.bytes(s.avg)], ["Pico", C.bytes(s.max)],
        ["Uso médio", C.pct((c.memory.pct_stats || {}).avg)], ["Contratada", C.bytes(c.memory.allocated_last)]]);
    }
    if (c.storage) {
      const t = (a) => (a || []).map((v) => (v === null ? null : v / 1024 ** 4));
      const series = [{ label: "Em uso", data: t(c.storage.used), kind: "used" }];
      if (c.storage.allocated) series.push({ label: "Limite", data: t(c.storage.allocated), kind: "limit" });
      C.line($("ch-sto"), labels, series, { fmt: (v) => `${C.num(v, 1)} TB` });
      const s = c.storage.stats;
      const first = c.storage.used.find((v) => v !== null);
      statLine("st-sto", [["Atual", C.bytes(s.last)], ["Variação", C.signed(first === undefined ? null : s.last - first, (v) => C.bytes(v))],
        ["Limite", c.storage.allocated_last ? C.bytes(c.storage.allocated_last) : "sem limite"]]);
    }
    const top = c.top_vms || { cpu: [], memory: [] };
    $("top-card").hidden = !top.cpu.length && !top.memory.length;
    const rows = (list) => list.map((v) => el("tr", null, el("td", { text: v.name }),
      el("td", { cls: "mono", text: C.pct(v.avg, 1) }), el("td", { cls: "mono", text: C.pct(v.peak, 1) })));
    $("top-cpu").tBodies[0].replaceChildren(...rows(top.cpu));
    $("top-mem").tBodies[0].replaceChildren(...rows(top.memory));
  }

  async function load() {
    showError("error", "");
    const q = state.tenant ? `tenant_id=${state.tenant}` : "";
    const start = new Date(Date.now() - state.days * 86400000).toISOString();
    $("to-report").href = `/relatorios.html${state.tenant ? `?tenant=${state.tenant}` : ""}`;
    try {
      const [o, c] = await Promise.all([
        api("GET", `/api/reports/overview?${q}`),
        api("GET", `/api/reports/consumption?${q}&start=${encodeURIComponent(start)}`)]);
      renderOverview(o);
      renderUsage(c);
    } catch (e) {
      showError("error", e.message);
    }
  }

  (async function () {
    const me = await boot();
    if (!me) return;
    let scope;
    try {
      scope = await api("GET", "/api/reports/scope");
    } catch (e) {
      $("main").hidden = false;
      showError("error", e.message);
      return;
    }
    const want = Number(new URLSearchParams(location.search).get("tenant")) || null;
    state.tenant = scope.tenants.some((t) => t.id === want) ? want : scope.default_tenant_id;
    const sel = $("tenant");
    sel.hidden = scope.tenants.length < 2;
    sel.replaceChildren(...scope.tenants.map((t) => el("option", {
      text: t.name + (t.has_vdc ? " · vCloud" : t.vms ? ` · ${t.vms} VMs` : ""), attrs: { value: String(t.id) } })));
    if (state.tenant) sel.value = String(state.tenant);
    sel.addEventListener("change", () => {
      state.tenant = Number(sel.value);
      history.replaceState(null, "", `?tenant=${state.tenant}`);
      load();
    });
    document.querySelectorAll("#range button").forEach((b) => b.addEventListener("click", () => {
      document.querySelectorAll("#range button").forEach((x) => x.classList.toggle("on", x === b));
      state.days = Number(b.getAttribute("data-days"));
      load();
    }));
    $("vm-q").addEventListener("input", renderVms);
    $("vm-more").addEventListener("click", () => { state.allVms = true; renderVms(); });
    $("main").hidden = false;
    if (!state.tenant) { showError("error", "Nenhum cliente disponível para o seu usuário."); return; }
    load();
  })();
})();
