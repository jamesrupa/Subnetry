"use strict";
// Setup: which optional tools are installed, with one-click installs where the platform allows.

let setupRun = null;

async function loadSetup(force = false) {
  const status = $("#setup-status");
  if (force) setStatus(status, "Checking…");
  let st;
  try {
    st = await api("/api/setup/status");
  } catch (err) {
    setStatus(status, esc(err.message), true);
    return;
  }
  const missing = st.tools.filter((t) => !t.installed).length;
  setStatus(status, missing ? `${missing} optional tool${missing === 1 ? " is" : "s are"} not installed yet.`
    : "Everything is installed. Subnetry is ready to go.");
  $("#setup-tools").innerHTML = st.tools.map((t) => `
    <div class="card setup-card ${t.installed ? "ok" : ""}">
      <div class="card-head"><h2>${esc(t.name)}</h2>
        ${t.installed ? '<span class="badge good-badge">✔ Installed</span>' : '<span class="badge">Not installed</span>'}</div>
      <p class="sub">Used by ${esc(t.used_by)}</p>
      <p>${esc(t.why)}</p>
      ${t.installed
        ? `<p class="sub mono setup-path">${esc(t.version || "")}${t.version ? "<br>" : ""}${esc(t.path)}</p>`
        : `<div class="setup-actions">${t.install.method === "link"
            ? `<a class="btn primary" href="${esc(t.install.url)}" target="_blank" rel="noopener noreferrer">${esc(t.install.label)} ↗</a>`
            : `<button class="btn primary" type="button" data-install="${esc(t.id)}">${esc(t.install.label)}</button>`}
          </div>${t.install.note ? `<p class="sub">${esc(t.install.note)}</p>` : ""}`}
    </div>`).join("");
  const helper = st.platform === "Darwin" ? " The Wi-Fi helper app is set up automatically the first time you open the Wi-Fi Scanner." : "";
  $("#setup-builtin").textContent = st.builtin.map((b) => `${b.name}: ${b.installed ? "available" : "not found"} (${b.note})`).join(" · ") + helper;
}
loaders.setup = () => loadSetup();

function setupInstall(tool) {
  if (setupRun) return;
  const card = $("#setup-log-card"), log = $("#setup-log");
  card.hidden = false;
  log.textContent = "";
  $("#setup-log-title").textContent = "Installing…";
  $("#setup-radar").innerHTML = radarSVG(28);
  document.querySelectorAll("[data-install]").forEach((b) => { b.disabled = true; });
  const add = (line) => { log.textContent += `${line}\n`; log.scrollTop = log.scrollHeight; };
  setupRun = stream(`/api/setup/install?tool=${encodeURIComponent(tool)}`, (ev) => {
    if (ev.type === "log") add(ev.line);
    if (ev.type === "done") { $("#setup-log-title").textContent = ev.ok ? "Done" : "Not finished yet"; add(ev.message); }
    if (ev.type === "error") { $("#setup-log-title").textContent = "Install failed"; add(ev.message); }
  }, (err) => {
    setupRun = null;
    $("#setup-radar").innerHTML = "";
    if (err) add(err.message);
    loadSetup();
  });
}

$("#setup-tools").addEventListener("click", (e) => { if (e.target.dataset.install) setupInstall(e.target.dataset.install); });
$("#setup-refresh").addEventListener("click", () => loadSetup(true));
