// OpenMon - aplica o branding (logo, favicon e banner de login) em todas as telas.
// Sem innerHTML e sem código inline (CSP estrita). Guarda as URLs no localStorage para trocar o logo
// já na abertura da página, sem piscar o padrão; depois confere com o servidor.
"use strict";

(function () {
  const KEY = "openmon.branding";
  const DEFAULT_ICON = "assets/openmon.svg";

  function read() {
    try { return JSON.parse(localStorage.getItem(KEY) || "null"); } catch (_) { return null; }
  }

  function write(b) {
    try { localStorage.setItem(KEY, JSON.stringify(b)); } catch (_) { /* navegação privada */ }
  }

  function setFavicon(item) {
    let link = document.querySelector("link[rel~='icon']");
    if (!link) {
      link = document.createElement("link");
      link.rel = "icon";
      document.head.append(link);
    }
    link.href = item ? item.url : DEFAULT_ICON;
    link.type = item ? item.mime : "image/svg+xml";
  }

  function setLogo(img, item, defaultAlt) {
    if (!img.dataset.defaultSrc) img.dataset.defaultSrc = img.getAttribute("src") || DEFAULT_ICON;
    if (item) {
      if (img.getAttribute("src") !== item.url) img.src = item.url;
      img.alt = "Logo";
      img.classList.add("brand-logo");
      img.removeAttribute("width");
      img.removeAttribute("height");
    } else {
      if (img.getAttribute("src") !== img.dataset.defaultSrc) img.src = img.dataset.defaultSrc;
      img.alt = defaultAlt;
      img.classList.remove("brand-logo");
      img.setAttribute("width", img.dataset.size || "28");
      img.setAttribute("height", img.dataset.size || "28");
    }
  }

  function apply(b) {
    b = b || {};
    setFavicon(b.favicon);
    document.querySelectorAll(".topbar .brand").forEach((brand) => {
      const img = brand.querySelector(":scope > img");
      const name = brand.querySelector(":scope > span");
      if (img) setLogo(img, b.logo, "");
      if (name) name.hidden = !!b.logo;  // o logo da empresa já traz o nome
      brand.classList.toggle("has-logo", !!b.logo);
    });
    // Cabeçalho dos relatórios (e de qualquer tela que marque o lugar do logo)
    document.querySelectorAll(".rep-head > img, img[data-brand-logo]").forEach((img) => {
      if (!img.dataset.size) img.dataset.size = img.getAttribute("width") || "40";
      setLogo(img, b.logo, "OpenMon");
    });
    const hero = document.getElementById("login-hero");
    if (hero) {
      const img = hero.querySelector("img");
      if (b.banner && img) {
        if (img.getAttribute("src") !== b.banner.url) img.src = b.banner.url;
        hero.hidden = false;
      } else {
        hero.hidden = true;
      }
      document.body.classList.toggle("with-hero", !!b.banner);
    }
  }

  async function refresh() {
    try {
      const res = await fetch("/api/branding", { cache: "no-store", credentials: "same-origin",
        headers: { Accept: "application/json" } });
      if (!res.ok) return;
      const b = await res.json();
      write(b);
      apply(b);
    } catch (_) { /* sem rede: fica o que estava */ }
  }

  function start() {
    apply(read());
    refresh();
  }

  window.OpenMonBranding = { apply, refresh };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
