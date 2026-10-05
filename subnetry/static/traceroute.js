"use strict";
// Traceroute: live hop-by-hop path with names, network owners, a latency chart and plain-English findings.

let tcRun = null;
let tcHops = new Map();   // hop number -> hop
let tcInfo = new Map();   // ip -> {hostname, scope, asn}
let tcStatusLoaded = false;

const TC_SCOPE = { local: ["Your network", "accent"], cgnat: ["Your ISP", ""] };

function tcTone(ms) {
  if (ms == null) return "none";
  return ms < 30 ? "good" : ms < 100 ? "warning" : "critical";
}

function tcAddressCell(h) {
  if (!h.ips.length) return `<span class="sub" style="display:inline">No reply</span>`;
  return h.ips.map((ip) => {
    const meta = tcInfo.get(ip) || {};
    const scope = TC_SCOPE[meta.scope || h.scopes?.[ip]];
    return `<div class="tc-addr">${meta.hostname ? `<b>${esc(meta.hostname)}</b>` : ""}
      <span class="mono${meta.hostname ? " sub" : ""}" ${meta.hostname ? 'style="display:inline"' : ""}>${esc(ip)}</span>
      ${scope ? `<span class="badge ${scope[1]}">${scope[0]}</span>` : ""}</div>`;
  }).join("");
}

function tcNetworkCell(h) {
  const asn = h.ips.map((ip) => tcInfo.get(ip)?.asn).find(Boolean);
  if (!asn) return `<span class="sub" style="display:inline">–</span>`;
  return `${esc(asn.org || `AS${asn.asn}`)}<span class="sub">AS${esc(asn.asn)}${asn.country ? ` · ${esc(asn.country)}` : ""}</span>`;
}

function tcRender() {
  const hops = [...tcHops.values()].sort((a, b) => a.hop - b.hop);
  $("#tc-rows").innerHTML = hops.map((h) => `<tr>
      <td class="num mono"><b>${h.hop}</b></td>
      <td>${tcAddressCell(h)}</td>
      <td>${tcNetworkCell(h)}</td>
      <td><div class="tc-probes">${h.rtts.map((r) => `<span class="tc-probe ${tcTone(r)}">${r == null ? "*" : `${r < 1 ? "<1" : r.toFixed(r < 10 ? 1 : 0)}`}</span>`).join("")}</div></td>
      <td class="num">${h.avg_ms == null ? "–" : `<span class="t-${tcTone(h.avg_ms)}">${h.avg_ms.toFixed(h.avg_ms < 10 ? 1 : 0)} ms</span>`}</td>
      <td class="num">${h.ips.length ? `<span class="${h.loss_pct ? "t-warning" : "sub"}" style="display:inline">${h.loss_pct}%</span>` : "–"}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="empty">Waiting for the first hop…</td></tr>`;
  if (hops.length) {
    barChart($("#tc-chart"), hops.map((h) => ({
      label: String(h.hop), value: h.avg_ms || 0,
      tip: `Hop ${h.hop}: ${h.ips.length ? `${h.ips.join(", ")} · ${h.avg_ms == null ? "no reply" : `${h.avg_ms} ms avg`}` : "no reply"}`,
    })), { ariaLabel: "Average round-trip time per hop" });
  }
}

function tcRenderPath(path) {
  $("#tc-path-card").hidden = !path.length;
  $("#tc-path").innerHTML = path.map((p, i) => `${i ? '<span class="tc-arrow" aria-hidden="true">→</span>' : ""}
    <span class="tc-node ${p.scope || ""}"><b>${esc(p.name === "your network" ? "Your network" : p.name === "your ISP" ? "Your ISP" : p.name)}</b>
      <span class="sub">hop${p.hops.length > 1 ? "s" : ""} ${p.hops.length > 1 ? `${p.hops[0]}–${p.hops[p.hops.length - 1]}` : p.hops[0]}${p.country ? ` · ${esc(p.country)}` : ""}</span></span>`).join("");
  const networks = path.filter((p) => p.scope === "public").length;
  $("#tc-path-note").textContent = networks ? `${networks} network${networks === 1 ? "" : "s"} on the internet` : "";
}

function tcStart(target) {
  if (tcRun) return;
  target = (target || $("#tc-target").value).trim();
  if (!target) return;
  $("#tc-target").value = target;
  tcHops = new Map();
  tcInfo = new Map();
  $("#tc-findings").innerHTML = "";
  $("#tc-path-card").hidden = true;
  $("#tc-chart").innerHTML = `<p class="sub">Hops appear here as the trace runs.</p>`;
  tcRender();
  const status = $("#tc-status");
  setStatus(status, `Tracing the route to ${esc(target)}…`);
  $("#tc-radar").innerHTML = radarSVG(32);
  $("#tc-start").hidden = true;
  $("#tc-stop").hidden = false;
  let resolved = target, maxHops = Number($("#tc-hops").value), finished = false;
  const params = new URLSearchParams({ target, max_hops: maxHops, resolve: $("#tc-resolve").checked });
  tcRun = stream(`/api/traceroute?${params}`, (ev) => {
    if (ev.type === "resolved") {
      resolved = ev.ip && ev.ip !== ev.name ? `${ev.name} (${ev.ip})` : ev.name;
      setStatus(status, `Tracing the route to ${esc(resolved)}…`);
    } else if (ev.type === "hop") {
      tcHops.set(ev.hop.hop, ev.hop);
      tcRender();
      setStatus(status, `Tracing the route to ${esc(resolved)}… hop ${ev.hop.hop} of up to ${maxHops}`);
    } else if (ev.type === "info") {
      tcInfo.set(ev.info.ip, ev.info);
      tcRender();
    } else if (ev.type === "done") {
      finished = true;
      Object.entries(ev.info).forEach(([ip, meta]) => tcInfo.set(ip, meta));
      ev.hops.forEach((h) => tcHops.set(h.hop, { ...tcHops.get(h.hop), ...h }));
      tcRender();
      tcRenderPath(ev.path);
      setStatus(status, `Finished: ${ev.hops.length} hop${ev.hops.length === 1 ? "" : "s"} to ${esc(resolved)} in ${ev.seconds}s.`);
      $("#tc-findings").innerHTML = ev.findings.length ? `<h2>What we noticed</h2>${ev.findings.map(recCard).join("")}` : "";
    } else if (ev.type === "error") {
      finished = true;
      setStatus(status, esc(ev.message), true);
    }
  }, (err) => {
    tcRun = null;
    $("#tc-radar").innerHTML = "";
    $("#tc-start").hidden = false;
    $("#tc-stop").hidden = true;
    if (err) setStatus(status, esc(err.message), true);
    else if (!finished) setStatus(status, `Stopped after ${tcHops.size} hop${tcHops.size === 1 ? "" : "s"}.`);
  });
}

/** Show a finished trace (e.g. from the Full Scan) in this tab. */
function tcShowResult(done) {
  if (tcRun) return;  // don't overwrite a trace that's running here
  tcHops = new Map(done.hops.map((h) => [h.hop, h]));
  tcInfo = new Map(Object.entries(done.info || {}));
  $("#tc-target").value = done.target;
  tcRender();
  tcRenderPath(done.path || []);
  setStatus($("#tc-status"), `From the Full Scan: ${done.hops.length} hop${done.hops.length === 1 ? "" : "s"} to ${esc(done.target)} in ${done.seconds}s.`);
  $("#tc-findings").innerHTML = done.findings?.length ? `<h2>What we noticed</h2>${done.findings.map(recCard).join("")}` : "";
}

async function loadTraceroute() {
  if (tcStatusLoaded) return;
  tcStatusLoaded = true;
  try {
    const st = await api("/api/traceroute/status");
    if (!st.installed) {
      $("#tc-missing").hidden = false;
      $("#tc-missing").innerHTML = `<h2>traceroute isn't available</h2><p>${esc(st.install_help)}</p>`;
      $("#tc-start").disabled = true;
    }
  } catch { /* the trace itself will report problems */ }
  // Offer the router as a quick target: tracing it checks the first, local hop on its own.
  const o = await loadOverview().catch(() => null);
  if (o?.gateway && !document.querySelector('#tc-examples [data-router]')) {
    $("#tc-examples").insertAdjacentHTML("beforeend",
      `<button type="button" class="chip" data-router data-target="${esc(o.gateway)}">Your router</button>`);
  }
}
loaders.trace = loadTraceroute;

$("#tc-form").addEventListener("submit", (e) => { e.preventDefault(); tcStart(); });
$("#tc-stop").addEventListener("click", () => tcRun?.stop());
$("#tc-examples").addEventListener("click", (e) => {
  const target = e.target.dataset?.target;
  if (target && !tcRun) tcStart(target);
});
