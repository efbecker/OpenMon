// OpenMon - problemas (alertas disparados) e reconhecimento. Sem innerHTML e sem código inline (CSP estrita).
"use strict";

(function () {
  const { $, el, api, boot, button, showError, when } = window.OpenMon;
  const SEV = { disaster: "Desastre", high: "Alta", average: "Média", warning: "Atenção", info: "Informação" };
  const ORDER = ["disaster", "high", "average", "warning", "info"];
  let data = { problems: [], counts: {}, tenants: [], can_ack: false };
  let timer = null;

  function duration(from, to) {
    const s = Math.max(0, ((to ? new Date(to) : new Date()) - new Date(from)) / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${Math.max(1, m)} min`;
  }

  function flash(msg) {
    $("list-ok").textContent = msg;
    $("list-ok").hidden = !msg;
  }

  function renderBar() {
    $("sev-bar").replaceChildren(...ORDER.map((s) => {
      const c = data.counts[s] || { open: 0, unack: 0 };
      return el("div", { cls: `sev-tile sev-${s}` + (c.open ? "" : " zero") },
        el("div", { cls: "k", text: SEV[s] }), el("div", { cls: "v", text: String(c.open) }),
        el("div", { cls: "muted small", text: c.open ? `${c.unack} sem reconhecer` : "" }));
    }));
  }

  function render() {
    $("table").tBodies[0].replaceChildren(...data.problems.map((p) => {
      const msg = el("td", null, el("div", { cls: "strong-line", text: p.message }));
      if (p.trigger_name) msg.append(el("div", { cls: "muted small", text: p.trigger_name }));
      const ack = el("td", { cls: "small" });
      if (p.acknowledged_at) {
        ack.append(el("div", { text: `${p.acknowledged_by || "—"} · ${when(p.acknowledged_at)}` }));
        if (p.ack_comment) ack.append(el("div", { cls: "muted", text: p.ack_comment }));
      } else {
        ack.append(el("span", { cls: "muted", text: "não" }));
      }
      const act = el("td");
      if (data.can_ack && p.status === "problem" && !p.acknowledged_at) {
        act.append(button("Reconhecer", "ghost", async () => {
          const comment = prompt("Comentário (opcional): o que está sendo feito?", "");
          if (comment === null) return;
          try {
            await api("POST", `/api/alerts/problems/${p.id}/ack`, { comment: comment.trim() || null });
            flash("Problema reconhecido; os canais do alerta foram avisados.");
            await load();
          } catch (e) {
            showError("list-error", e.message);
          }
        }));
      }
      const sev = el("td", null, el("span", { cls: `sev-tag sev-${p.severity}`, text: SEV[p.severity] || p.severity }));
      if (p.status === "resolved") sev.append(el("div", { cls: "good small", text: "resolvido" }));
      return el("tr", { cls: p.status === "resolved" ? "row-off" : "" }, sev, msg, el("td", { text: p.tenant_name }),
        el("td", { cls: "small", text: when(p.opened_at) }),
        el("td", { cls: "small", text: duration(p.opened_at, p.resolved_at) }), ack, act);
    }));
    $("count").textContent = data.problems.length ? `(${data.problems.length})` : "";
    $("empty").hidden = data.problems.length > 0;
    $("empty").textContent = $("filter-status").value === "open" ? "Nenhum problema em aberto." : "Nenhum problema no período.";
  }

  async function load() {
    const q = new URLSearchParams({ status: $("filter-status").value });
    if ($("filter-tenant").value) q.set("tenant_id", $("filter-tenant").value);
    try {
      data = await api("GET", "/api/alerts/problems?" + q.toString());
      showError("list-error", "");
      const cur = $("filter-tenant").value;
      $("filter-tenant").replaceChildren(el("option", { text: "Todos os tenants", attrs: { value: "" } }),
        ...data.tenants.map((t) => el("option", { text: t.name, attrs: { value: String(t.id) } })));
      $("filter-tenant").value = cur;
      $("filter-tenant").hidden = data.tenants.length < 2;
      $("btn-config").hidden = !data.can_manage;
      renderBar();
      render();
    } catch (e) {
      showError("list-error", e.message);
    }
  }

  $("filter-status").addEventListener("change", load);
  $("filter-tenant").addEventListener("change", load);

  (async function () {
    const me = await boot();
    if (!me) return;
    $("main").hidden = false;
    await load();
    timer = setInterval(() => { if (!document.hidden) load(); }, 30000);
  })();
})();
