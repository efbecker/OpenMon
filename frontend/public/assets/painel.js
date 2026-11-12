// OpenMon - painel do cliente: contratado x em uso, consumo no período (as VMs ficam na tela VMs). Sem innerHTML (CSP estrita).
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
    $("main").hidden = false;
    if (!state.tenant) { showError("error", "Nenhum cliente disponível para o seu usuário."); return; }
    load();
  })();
})();
