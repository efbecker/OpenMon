// OpenMon - gráficos (Chart.js 4, versionado em assets/vendor) e formatação pt-BR. Sem código inline (CSP).
"use strict";

window.OpenMon = window.OpenMon || {};
window.OpenMon.charts = (function () {
  // Paleta validada para o fundo escuro (#111827): em uso = verde, segunda série = azul, contratado = cinza tracejado
  const COLOR = { used: "#059669", second: "#3b82f6", limit: "#94a3b8", grid: "#1f2a3c", text: "#94a3b8" };
  const nf = (d) => new Intl.NumberFormat("pt-BR", { maximumFractionDigits: d === undefined ? 1 : d });
  const KB = 1024;

  function num(v, d) { return v === null || v === undefined || isNaN(v) ? "—" : nf(d).format(v); }

  // Bytes em base 1024 (GB, TB) como no vCloud
  function bytes(v, d) {
    if (v === null || v === undefined || isNaN(v)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0;
    let x = Number(v);
    while (Math.abs(x) >= KB && i < u.length - 1) { x /= KB; i += 1; }
    return `${nf(d === undefined ? (x >= 100 ? 0 : 1) : d).format(x)} ${u[i]}`;
  }
  function gb(v) { return v === null || v === undefined ? "—" : `${nf(0).format(v / KB ** 3)} GB`; }
  function ghz(mhz) { return mhz === null || mhz === undefined ? "—" : `${nf(1).format(mhz / 1000)} GHz`; }
  function pct(v, d) { return v === null || v === undefined ? "—" : `${nf(d === undefined ? 0 : d).format(v)}%`; }
  function signed(v, fmt) {
    if (v === null || v === undefined) return "—";
    return (v > 0 ? "+" : v < 0 ? "−" : "") + fmt(Math.abs(v));
  }

  function setup() {
    if (!window.Chart || setup.done) return;
    setup.done = true;
    const C = window.Chart;
    C.defaults.font.family = getComputedStyle(document.body).fontFamily;
    C.defaults.font.size = 12;
    C.defaults.color = COLOR.text;
    C.defaults.borderColor = COLOR.grid;
    C.defaults.animation = false;
    C.defaults.maintainAspectRatio = false;
  }

  // Rótulo do eixo X conforme o tamanho do período
  function timeLabel(iso, stepSeconds) {
    const d = new Date(iso);
    if (stepSeconds && stepSeconds >= 86400) return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", year: "2-digit" });
    if (stepSeconds && stepSeconds >= 3 * 3600) return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit" }) + "h";
    return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  const registry = new WeakMap();

  // series: [{label, data, kind: "used" | "limit" | "second", fill}] · fmt: valor -> texto
  function line(canvas, labels, series, opts) {
    setup();
    if (!window.Chart || !canvas) return null;
    opts = opts || {};
    const old = registry.get(canvas);
    if (old) old.destroy();
    const fmt = opts.fmt || ((v) => num(v));
    const datasets = series.map((s) => {
      const c = COLOR[s.kind || "used"];
      const limit = s.kind === "limit";
      return {
        label: s.label, data: s.data, borderColor: c, backgroundColor: limit ? c : c + "33",
        fill: limit ? false : s.fill !== false, borderWidth: limit ? 1.5 : 2, borderDash: limit ? [6, 5] : [],
        pointRadius: 0, pointHoverRadius: limit ? 0 : 4, pointHitRadius: 8, tension: opts.stepped ? 0 : 0.2,
        stepped: opts.stepped ? "before" : false, spanGaps: false,
      };
    });
    const chart = new window.Chart(canvas, {
      type: "line",
      data: { labels, datasets },
      options: {
        responsive: true, interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: series.length > 1, position: "top", align: "end",
            labels: { boxWidth: 14, boxHeight: 2, color: "#cbd5e1" } },
          tooltip: { backgroundColor: "#0f172a", borderColor: "#2a3850", borderWidth: 1, titleColor: "#e5e7eb",
            bodyColor: "#e5e7eb", padding: 10,
            callbacks: { label: (x) => ` ${x.dataset.label}: ${x.parsed.y === null ? "—" : fmt(x.parsed.y)}` } },
        },
        scales: {
          x: { grid: { display: false }, ticks: { maxTicksLimit: opts.xTicks || 5, maxRotation: 0, autoSkip: true } },
          y: { beginAtZero: opts.beginAtZero !== false, suggestedMax: opts.suggestedMax,
            grid: { color: COLOR.grid }, border: { display: false },
            ticks: { maxTicksLimit: 5, callback: (v) => fmt(v) } },
        },
      },
    });
    registry.set(canvas, chart);
    return chart;
  }

  return { COLOR, num, bytes, gb, ghz, pct, signed, line, timeLabel };
})();
