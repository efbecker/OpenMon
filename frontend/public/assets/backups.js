// OpenMon - backups (Veeam): jobs, SLA por tenant e repositórios. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const RESULT = { success: ["tag-ok", "sucesso"], warning: ["tag-auto", "aviso"], failed: ["tag-bad", "falhou"],
    running: ["tag-you", "rodando"], canceled: ["tag-off", "cancelado"], none: ["tag-off", "nunca rodou"] };
  let data = { jobs: [], tenants: [], repositories: [] };
  let allTenants = [];

  function tag(result) {
    const [cls, label] = RESULT[result] || ["tag-off", result || "—"];
    return el("span", { cls: "tag " + cls, text: label });
  }

  function bytes(v) {
    if (v === null || v === undefined) return "—";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0;
    let n = Number(v);
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i += 1; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  function ago(iso) {
    if (!iso) return "";
    const h = (Date.now() - new Date(iso).getTime()) / 3600000;
    if (h < 1) return `há ${Math.max(1, Math.round(h * 60))} min`;
    if (h < 48) return `há ${Math.round(h)} h`;
    return `há ${Math.round(h / 24)} dias`;
  }

  function duration(s) {
    if (s === null || s === undefined) return "—";
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return h ? `${h} h ${m} min` : `${m} min ${s % 60} s`;
  }

  function slaTag(j) {
    if (j.in_sla === null) return el("span", { cls: "tag tag-off", text: j.is_enabled ? "sem SLA" : "desabilitado" });
    return el("span", { cls: "tag " + (j.in_sla ? "tag-ok" : "tag-bad"), text: (j.in_sla ? "em dia" : "fora do SLA") + ` · ${j.sla_hours} h` });
  }

  // Admin: vincula o job ou o repositório a um tenant (fixado: a coleta e as regras não mudam mais)
  function tenantCell(item, path) {
    const td = el("td");
    if (!data.can_manage || !(data.tenant_choices || []).length) {
      td.append(item.tenant_name || "—");
      return td;
    }
    const sel = el("select", { cls: "tenant-pick", attrs: { "aria-label": `Tenant de ${item.name}` } },
      ...data.tenant_choices.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
    sel.value = String(item.tenant_id);
    const save = button("Vincular", "primary", async () => {
      save.disabled = true;
      try {
        await api("PUT", path, { tenant_id: Number(sel.value), tenant_locked: true, is_monitored: true });
        showError("list-error", "");
        await load();
      } catch (e) {
        showError("list-error", e.message);
        save.disabled = false;
      }
    });
    save.hidden = true;
    sel.addEventListener("change", () => { save.hidden = sel.value === String(item.tenant_id); });
    td.append(sel, save);
    if (item.tenant_locked) td.append(el("div", { cls: "muted small", text: "fixo" }));
    return td;
  }

  function renderSummary() {
    $("summary").replaceChildren(...data.tenants.map((t) => {
      const withSla = t.in_sla + t.out_of_sla;
      const v = el("div", { cls: "v" });
      if (withSla) {
        v.append(el("span", { cls: t.out_of_sla ? "bad" : "good", text: `${t.in_sla}/${withSla} em dia` }));
        v.append(el("span", { cls: "muted small", text: ` · SLA ${t.sla_hours} h` }));
      } else {
        v.append(el("span", { text: `${t.jobs} job(s)` }), el("span", { cls: "muted small", text: " · sem SLA definido" }));
      }
      if (t.failed) v.append(el("div", { cls: "bad small", text: `${t.failed} com a última execução falhando` }));
      const tile = el("button", { cls: "stat stat-btn" + ($("filter-tenant").value === String(t.tenant_id) ? " on" : ""), attrs: { type: "button" } },
        el("div", { cls: "k", text: t.tenant_name }), v);
      tile.addEventListener("click", () => {
        $("filter-tenant").value = $("filter-tenant").value === String(t.tenant_id) ? "" : String(t.tenant_id);
        load();
      });
      return tile;
    }));
    $("summary").hidden = data.tenants.length < 1;
  }

  function render() {
    const state = $("filter-state").value;
    const jobs = data.jobs.filter((j) => !state || (state === "out" ? j.in_sla === false : j.last_result === "failed"));
    $("table").tBodies[0].replaceChildren(...jobs.map((j) => {
      const name = el("td", null, el("strong", { text: j.name }));
      if (j.schedule_desc) name.append(el("div", { cls: "muted small", text: j.schedule_desc }));
      const last = el("td", { cls: "small" }, when(j.last_run_at, "—"));
      const good = el("td", { cls: "small" }, j.last_success_at ? when(j.last_success_at) : "nunca");
      if (j.last_success_at) good.append(el("div", { cls: "muted", text: ago(j.last_success_at) }));
      return el("tr", { cls: !j.is_enabled ? "row-off" : j.in_sla === false || j.last_result === "failed" ? "row-warn" : "" },
        name, tenantCell(j, `/api/backups/${j.id}/tenant`), el("td", { text: j.job_type || "—" }), last,
        el("td", null, tag(j.last_result)), good, el("td", null, slaTag(j)), el("td", { cls: "small", text: j.repository_name || "—" }),
        el("td", null, button("Histórico", "ghost", () => openRuns(j))));
    }));
    $("count").textContent = data.jobs.length ? `(${data.jobs.length})` : "";
    $("empty").hidden = data.jobs.length > 0;
  }

  function renderRepos() {
    const repos = data.repositories || [];
    $("repos").tBodies[0].replaceChildren(...repos.map((r) => {
      const use = r.capacity_bytes ? Math.round(100 * (1 - (r.free_bytes || 0) / r.capacity_bytes)) : null;
      return el("tr", { cls: use !== null && use >= 90 ? "row-warn" : "" }, el("td", null, el("strong", { text: r.name })),
        tenantCell(r, `/api/admin/assets/${r.id}`), el("td", { text: r.hostname || "—" }), el("td", { text: r.model || "—" }), el("td", { cls: "mono small", text: r.path || "—" }),
        el("td", { text: bytes(r.capacity_bytes) }), el("td", { text: bytes(r.free_bytes) }),
        el("td", { cls: use !== null && use >= 90 ? "bad" : "", text: use === null ? "—" : `${use}%` }),
        el("td", null, el("span", { cls: "tag " + (r.status === "up" ? "tag-ok" : "tag-bad"), text: r.status === "up" ? "online" : "offline" })));
    }));
    $("repos-count").textContent = repos.length ? `(${repos.length})` : "";
    $("repos-card").hidden = !repos.length;
  }

  async function openRuns(j) {
    $("runs-title").textContent = `Histórico · ${j.name}`;
    $("runs").tBodies[0].replaceChildren(el("tr", null, el("td", { cls: "muted", text: "Carregando…", attrs: { colspan: "5" } })));
    $("runs-card").hidden = false;
    $("runs-card").scrollIntoView({ behavior: "smooth", block: "start" });
    try {
      const r = await api("GET", `/api/backups/${j.id}/runs`);
      $("runs").tBodies[0].replaceChildren(...(r.runs.length ? r.runs.map((x) => el("tr", { cls: x.result === "failed" ? "row-warn" : "" },
        el("td", { cls: "small", text: when(x.started_at) }), el("td", { cls: "small", text: when(x.ended_at, "—") }),
        el("td", { text: duration(x.duration_s) }), el("td", null, tag(x.result)),
        el("td", { cls: "small wrap", text: x.message || "" })))
        : [el("tr", null, el("td", { cls: "muted", text: "Nenhuma execução registrada ainda.", attrs: { colspan: "5" } }))]));
    } catch (e) {
      $("runs").tBodies[0].replaceChildren(el("tr", null, el("td", { cls: "error-text", text: e.message, attrs: { colspan: "5" } })));
    }
  }

  async function load() {
    const q = new URLSearchParams();
    if ($("filter-tenant").value) q.set("tenant_id", $("filter-tenant").value);
    try {
      data = await api("GET", "/api/backups?" + q.toString());
      showError("list-error", "");
      if (!allTenants.length || !$("filter-tenant").value) {
        allTenants = data.tenants.map((t) => ({ id: t.tenant_id, name: t.tenant_name }));
        const cur = $("filter-tenant").value;
        $("filter-tenant").replaceChildren(el("option", { text: "Todos os tenants", attrs: { value: "" } }),
          ...allTenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
        $("filter-tenant").value = cur;
      }
      $("filter-tenant").hidden = allTenants.length < 2;
      renderSummary();
      render();
      renderRepos();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  $("filter-tenant").addEventListener("change", load);
  $("filter-state").addEventListener("change", render);
  $("btn-close").addEventListener("click", () => { $("runs-card").hidden = true; });

  (async function () {
    const me = await boot();
    if (!me) return;
    if (me.user.scope !== "global") $("intro").textContent = "Seus jobs de backup, a última execução e o SLA contratado: o job está em dia quando o último backup bom terminou dentro das horas contratadas.";
    $("main").hidden = false;
    load();
  })();
})();
