// OpenMon - assistente de deploy do banco (Servidor 2).
// Sem dependências e sem innerHTML com dados externos (tudo via textContent): compatível com a CSP estrita.
"use strict";

(function () {
  const TOKEN_KEY = "openmon.setupToken";
  const $ = (id) => document.getElementById(id);

  let token = "";
  try { token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch (_) { /* navegação privada */ }

  let verified = null;        // {host, port, username, fingerprint} após login testado
  let pendingFingerprint = null;
  let pollTimer = null;
  let nextEvent = 0;
  let deploying = false;

  // ---------------------------------------------------------------- API
  async function api(method, path, body) {
    const opts = { method, headers: { "X-Setup-Token": token, "Accept": "application/json" }, cache: "no-store" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      const err = new Error(errorText(data) || `Erro HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function errorText(data) {
    if (!data) return "";
    if (typeof data.detail === "string") return data.detail;
    if (Array.isArray(data.detail)) {
      return data.detail.map((d) => {
        const field = Array.isArray(d.loc) ? d.loc[d.loc.length - 1] : "";
        return `${field}: ${String(d.msg || "").replace(/^Value error, /, "")}`;
      }).join("\n");
    }
    return "";
  }

  // ---------------------------------------------------------------- telas
  function show(id, visible) { $(id).hidden = !visible; }

  function setError(id, message) {
    const el = $(id);
    el.textContent = message || "";
    el.hidden = !message;
  }

  async function boot() {
    let status;
    try {
      status = await api("GET", "/api/setup/status");
    } catch (e) {
      showClosed("API indisponível", "Não foi possível falar com o serviço openmon-api. No Servidor 1: sudo systemctl status openmon-api");
      return;
    }
    if (!status.setup_open) {
      if (status.admin_created || status.db_provisioned) {
        location.replace("/login.html");  // instalação concluída: o sistema começa no login
        return;
      }
      showClosed("Assistente de instalação encerrado",
        "Não há token de instalação ativo. No Servidor 1, rode o instalador de novo (o mesmo comando curl) para gerar um novo token.");
      return;
    }
    if (token) {
      try { await api("POST", "/api/setup/token/verify"); return showWizard(status); } catch (_) { token = ""; }
    }
    show("token-card", true);
    $("token-input").focus();
  }

  function showClosed(title, text) {
    $("closed-title").textContent = title;
    $("closed-text").textContent = text;
    show("closed-card", true);
    show("token-card", false);
    show("deploy-card", false);
    show("admin-card", false);
  }

  function showDeploy() {
    show("admin-card", false);
    show("deploy-card", true);
    show("terminal-card", true);
    $("host").focus();
  }

  function showWizard(status) {
    show("token-card", false);
    if (status && status.deploy_status === "running") {
      // Recarregou a página no meio do deploy: retoma o terminal
      showDeploy();
      startPolling();
      return;
    }
    if (status && status.db_provisioned) return showAdminStep();
    showDeploy();
  }

  // ---------------------------------------------------------------- administrador
  async function showAdminStep() {
    setError("admin-error", "");
    let r;
    try {
      r = await api("GET", "/api/setup/admin");
    } catch (e) {
      show("admin-card", true);
      show("admin-form", true);
      show("admin-exists", false);
      setError("admin-error", e.message);
      return;
    }
    show("deploy-card", false);
    show("admin-card", true);
    show("admin-form", r.needed);
    show("admin-exists", !r.needed);
    $("admin-card").scrollIntoView({ behavior: "smooth", block: "start" });
    if (r.needed) $("admin-password").focus();
  }

  function setupDone(username) {
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (_) { /* ignora */ }
    token = "";
    ["admin-card", "deploy-card", "terminal-card", "token-card"].forEach((id) => show(id, false));
    show("done-card", true);
    const target = username ? `/login.html?u=${encodeURIComponent(username)}` : "/login.html";
    $("done-link").href = target;
    $("done-text").textContent = username
      ? `Administrador "${username}" criado. Redirecionando para a tela de login…`
      : "Assistente encerrado. Redirecionando para a tela de login…";
    setTimeout(() => location.assign(target), 2500);
  }

  $("admin-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    setError("admin-error", "");
    const pw = $("admin-password").value;
    if (pw.length < 12) return setError("admin-error", "A senha precisa ter pelo menos 12 caracteres.");
    if (pw !== $("admin-password2").value) return setError("admin-error", "As senhas não conferem.");
    const body = {
      username: $("admin-username").value.trim(),
      display_name: $("admin-name").value.trim() || null,
      email: $("admin-email").value.trim() || null,
      password: pw,
      password_confirm: $("admin-password2").value,
    };
    $("btn-admin").disabled = true;
    try {
      const r = await api("POST", "/api/setup/admin", body);
      $("admin-password").value = "";
      $("admin-password2").value = "";
      setupDone(r.username);
    } catch (e) {
      if (e.status === 409 && /administrador/.test(e.message)) {
        show("admin-form", false);
        show("admin-exists", true);
      } else {
        setError("admin-error", e.message);
      }
    } finally {
      $("btn-admin").disabled = false;
    }
  });

  $("btn-finish").addEventListener("click", async () => {
    try {
      await api("POST", "/api/setup/finish");
      setupDone("");
    } catch (e) {
      setError("admin-error", e.message);
    }
  });

  ["btn-redeploy", "btn-redeploy2"].forEach((id) => $(id).addEventListener("click", showDeploy));
  $("btn-to-admin").addEventListener("click", showAdminStep);

  $("token-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    setError("token-error", "");
    token = $("token-input").value.trim();
    try {
      await api("POST", "/api/setup/token/verify");
      try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* ignora */ }
      $("token-input").value = "";
      const status = await api("GET", "/api/setup/status");
      showWizard(status);
    } catch (e) {
      setError("token-error", e.message);
    }
  });

  // ---------------------------------------------------------------- formulário
  function formValues() {
    return {
      host: $("host").value.trim(),
      port: parseInt($("port").value, 10) || 22,
      username: $("username").value.trim(),
      password: $("password").value,
      sudo_password: $("sudo-password").value || null,
    };
  }

  function invalidateVerification() {
    verified = null;
    pendingFingerprint = null;
    $("btn-deploy").disabled = true;
    show("fp-box", false);
    show("probe-box", false);
  }

  ["host", "port", "username"].forEach((id) => $(id).addEventListener("input", invalidateVerification));
  $("username").addEventListener("input", () => show("root-note", $("username").value.trim() === "root"));

  $("host").addEventListener("change", async () => {
    const host = $("host").value.trim();
    if (!host || $("frontend").dataset.touched === "1") return;
    try {
      const r = await api("POST", "/api/setup/database/frontend-ip", { host });
      if (r.ip) $("frontend").value = r.ip;
    } catch (_) { /* o usuário preenche à mão */ }
  });
  $("frontend").addEventListener("input", () => { $("frontend").dataset.touched = "1"; });

  $("btn-test").addEventListener("click", async () => {
    setError("form-error", "");
    invalidateVerification();
    const v = formValues();
    if (!v.host || !v.username) return setError("form-error", "Preencha o IP do Servidor 2 e o usuário SSH.");
    busy(true, "Lendo a chave SSH…");
    try {
      const r = await api("POST", "/api/setup/database/ssh-test", { host: v.host, port: v.port, username: v.username });
      pendingFingerprint = r.fingerprint;
      $("fp-type").textContent = r.key_type;
      $("fp-value").textContent = r.fingerprint;
      show("fp-box", true);
      $("fp-confirm").focus();
    } catch (e) {
      setError("form-error", e.message);
    } finally {
      busy(false);
    }
  });

  $("fp-confirm").addEventListener("click", async () => {
    setError("form-error", "");
    const v = formValues();
    if (!v.password) return setError("form-error", "Informe a senha SSH.");
    busy(true, "Autenticando e verificando o Servidor 2…");
    try {
      const r = await api("POST", "/api/setup/database/ssh-test", { ...v, fingerprint: pendingFingerprint });
      verified = { host: v.host, port: v.port, username: v.username, fingerprint: pendingFingerprint };
      show("fp-box", false);
      fillList("probe-list", [
        ["Sistema", r.os], ["Arquitetura", r.arch], ["Hostname", r.hostname],
        ["CPU", `${r.cpus} vCPU`], ["Memória", `${(r.mem_mb / 1024).toFixed(1)} GB`],
        ["Disco", `${r.disk_gb} GB · ${r.disk_type}`],
        ["Privilégio", { root: "root", nopasswd: "sudo sem senha", password: "sudo com senha" }[r.sudo] || r.sudo],
        ["Chave SSH", verified.fingerprint],
      ]);
      $("probe-title").textContent = `Conexão SSH verificada com ${v.username}@${v.host}`;
      show("probe-box", true);
      $("btn-deploy").disabled = deploying;
    } catch (e) {
      setError("form-error", e.message);
    } finally {
      busy(false);
    }
  });

  $("deploy-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    setError("form-error", "");
    const v = formValues();
    if (!verified || verified.host !== v.host || verified.port !== v.port || verified.username !== v.username) {
      return setError("form-error", "Teste a conexão SSH e confirme a chave antes do deploy.");
    }
    const frontend = $("frontend").value.trim();
    if (!frontend) return setError("form-error", "Informe o IP do Servidor 1.");
    const body = { ...v, fingerprint: verified.fingerprint, frontend_address: frontend,
                   ssh_allow: $("ssh-allow").value.trim() || null };
    try {
      clearTerminal();
      await api("POST", "/api/setup/database/deploy", body);
      $("password").value = "";
      $("sudo-password").value = "";
      startPolling();
    } catch (e) {
      setError("form-error", e.message);
    }
  });

  function busy(on, message) {
    $("btn-test").disabled = on || deploying;
    $("fp-confirm").disabled = on;
    if (on && message) term("dim", `[OpenMon SSH Engine] ${message}`);
  }

  function fillList(id, rows) {
    const dl = $(id);
    dl.replaceChildren();
    rows.forEach(([k, v]) => {
      if (v === undefined || v === null || v === "") return;
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = String(v);
      dl.append(dt, dd);
    });
  }

  // ---------------------------------------------------------------- terminal
  function term(kind, text) {
    const box = $("terminal");
    const line = document.createElement("div");
    line.className = `line ${kind}`;
    const prefix = { step: "==> ", warn: "[AVISO] ", error: "[ERRO] ", success: "✔ ", info: "  · " }[kind] || "";
    line.textContent = prefix + text;
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    box.append(line);
    if (atBottom) box.scrollTop = box.scrollHeight;
  }

  function clearTerminal() {
    $("terminal").replaceChildren();
    nextEvent = 0;
    show("result-box", false);
  }

  $("btn-clear").addEventListener("click", () => { if (!deploying) clearTerminal(); });
  $("btn-copy").addEventListener("click", async () => {
    const text = Array.from($("terminal").children).map((l) => l.textContent).join("\n");
    try { await navigator.clipboard.writeText(text); } catch (_) { /* sem permissão */ }
  });

  function setDeploying(on) {
    deploying = on;
    $("btn-deploy").disabled = on || !verified;
    $("btn-test").disabled = on;
    $("btn-deploy").textContent = on ? "Deploy em andamento…" : "Fazer Deploy do Banco de Dados no Servidor 2";
    Array.from(document.querySelectorAll("#deploy-form input")).forEach((i) => { i.disabled = on; });
  }

  function startPolling() {
    setDeploying(true);
    show("progress", true);
    $("bar-fill").classList.remove("failed");
    if (pollTimer) clearTimeout(pollTimer);
    poll();
  }

  async function poll() {
    let snap;
    try {
      snap = await api("GET", `/api/setup/database/deploy?since=${nextEvent}`);
    } catch (e) {
      term("error", `Falha ao ler o andamento: ${e.message}`);
      pollTimer = setTimeout(poll, 3000);
      return;
    }
    snap.events.forEach((ev) => {
      term(ev.kind, ev.message);
      $("bar-fill").style.width = `${ev.percent}%`;
      $("progress-pct").textContent = `${ev.percent}%`;
      if (ev.kind === "step") $("progress-step").textContent = ev.message;
    });
    nextEvent = snap.next;
    if (snap.status === "running") {
      pollTimer = setTimeout(poll, 1000);
      return;
    }
    setDeploying(false);
    finish(snap);
  }

  function finish(snap) {
    const r = snap.result || {};
    const ok = snap.status === "success";
    const box = $("result-box");
    box.classList.toggle("failed", !ok);
    if (!ok) $("bar-fill").classList.add("failed");
    $("progress-step").textContent = ok ? "Concluído" : "Falhou";
    $("result-title").textContent = ok ? "Banco de dados provisionado com sucesso" : "O deploy não foi concluído";
    const info = r.info || {};
    fillList("result-list", ok ? [
      ["Servidor", `${r.host}:${r.port}`], ["Banco", r.database],
      ["PostgreSQL", info.server_version], ["TimescaleDB", info.timescaledb_version],
      ["TLS", info.ssl === "on" ? "ativo (verify-full)" : info.ssl], ["shared_buffers", info.shared_buffers],
      ["Hypertables", info.hypertables], ["Continuous aggregates", info.continuous_aggregates],
      ["Jobs de compressão/retenção", info.background_jobs], ["Schema", info.schema_version],
    ] : [["Erro", r.error || "veja o terminal acima"]]);
    $("result-note").textContent = ok
      ? "As credenciais SSH foram descartadas e a configuração do banco foi gravada em /etc/openmon/database/. Falta só criar o administrador."
      : "Nada foi gravado no Servidor 1. Corrija o problema e rode o deploy de novo: ele é idempotente.";
    show("result-box", true);
    show("result-actions", ok);
    if (ok) {
      show("deploy-card", false);
      showAdminStep();
    }
  }

  boot();
})();
