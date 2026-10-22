"use strict";
// Subnetry website: pick the right download for this computer, show the latest release, install tabs.

const REPO = "jamesrupa/Subnetry";
const ASSETS = {
  "mac-arm64": { file: "Subnetry-mac-arm64.dmg", label: "Download for Mac", os: "macOS · Apple Silicon" },
  "mac-intel": { file: "Subnetry-mac-intel.dmg", label: "Download for Intel Mac", os: "macOS · Intel" },
  windows: { file: "Subnetry-Setup-windows-x64.exe", label: "Download for Windows", os: "Windows" },
};
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** "mac-arm64" | "mac-intel" | "mac" (chip unknown) | "windows" | "other" */
async function detectPlatform() {
  const ua = navigator.userAgent || "";
  const uaData = navigator.userAgentData;
  const platform = (uaData && uaData.platform) || navigator.platform || "";
  if (/Win/i.test(platform) || /Windows/i.test(ua)) return "windows";
  if (!/Mac/i.test(platform) && !/Macintosh|Mac OS X/i.test(ua)) return "other";
  if (navigator.maxTouchPoints > 1) return "other"; // iPad reports itself as a Mac
  try {
    if (uaData && uaData.getHighEntropyValues) {  // Chrome, Edge
      const { architecture } = await uaData.getHighEntropyValues(["architecture"]);
      if (architecture === "arm") return "mac-arm64";
      if (architecture === "x86") return "mac-intel";
    }
  } catch { /* not available */ }
  try {  // Safari and Firefox: the graphics chip name gives Apple Silicon away
    const gl = document.createElement("canvas").getContext("webgl");
    const ext = gl && gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : "";
    if (/Apple M\d/i.test(renderer)) return "mac-arm64";  // Safari says just "Apple GPU" on every Mac: no hint
    if (/Intel|AMD|Radeon/i.test(renderer)) return "mac-intel";
  } catch { /* not available */ }
  return "mac";
}

function formatSize(bytes) {
  return bytes >= 1e6 ? `${(bytes / 1e6).toFixed(0)} MB` : `${Math.round(bytes / 1e3)} KB`;
}

async function latestRelease() {
  try {
    const r = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } });
    if (r.status === 404) return { none: true };
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;  // offline or blocked: keep the static links
  }
}

function setupTabs(initial) {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab, focus) => {
    tabs.forEach((t) => {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
    if (focus) tab.focus();
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      select(tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length], true);
    });
  });
  if (initial === "windows") select($("#tab-win"));
}

async function main() {
  const platform = await detectPlatform();
  setupTabs(platform);
  const mine = ASSETS[platform];
  $("#t-os").textContent = mine ? mine.os : platform === "mac" ? "macOS" : "Not Mac or Windows";

  // Highlight this computer's download and point the hero button straight at it.
  const cards = platform === "mac" ? ["mac-arm64", "mac-intel"] : mine ? [platform] : [];
  cards.forEach((p) => {
    const card = document.querySelector(`.dl[data-platform="${p}"]`);
    card.classList.add("mine");
    card.querySelector(".btn").classList.add("primary");
  });
  document.querySelectorAll(".dl").forEach((card) => {
    if (!cards.includes(card.dataset.platform)) card.querySelector(".btn").classList.remove("primary");
  });
  const hero = $("#hero-download");
  if (mine) {
    hero.textContent = mine.label;
    hero.href = `https://github.com/${REPO}/releases/latest/download/${mine.file}`;
  }

  const rel = await latestRelease();
  const dot = $("#t-dot"), state = $("#t-state");
  if (rel && rel.none) {
    dot.classList.add("soon");
    state.textContent = "FIRST RELEASE SOON";
    $("#t-version").textContent = "–";
    $("#dl-status").textContent = "The first release is on its way. Until then, the source code and build instructions are on GitHub.";
    document.querySelectorAll("[data-asset]").forEach((a) => { a.setAttribute("aria-disabled", "true"); a.removeAttribute("href"); });
    hero.href = "#download";
    $("#hero-note").textContent = "First release coming soon · Free · No account";
    return;
  }
  if (!rel) {
    state.textContent = "READY";
    dot.classList.add("live");
    return;
  }
  dot.classList.add("live");
  state.textContent = "AVAILABLE";
  const version = rel.tag_name || "";
  const date = rel.published_at ? new Date(rel.published_at) : null;
  $("#t-version").textContent = version;
  $("#t-date").textContent = date ? date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "–";
  const sizes = Object.fromEntries((rel.assets || []).map((a) => [a.name, a.size]));
  document.querySelectorAll(".dl").forEach((card) => {
    const link = card.querySelector("[data-asset]");
    const size = sizes[link.dataset.asset];
    if (size) card.querySelector("[data-size]").textContent = `${link.dataset.asset.endsWith(".dmg") ? ".dmg" : ".exe"} · ${formatSize(size)}`;
  });
  $("#dl-release").innerHTML = `Version ${esc(version)}${date ? `, released ${esc(date.toLocaleDateString())}` : ""}. `
    + `<a href="${esc(rel.html_url)}">What's new</a> · <a href="https://github.com/${REPO}/releases">older versions</a>.`;
}

main();
