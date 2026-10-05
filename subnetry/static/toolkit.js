"use strict";
// Toolkit: subnet calculator, MAC vendor lookup, port reference and DNS lookup/explainer.

const fmtInt = (n) => (typeof n === "number" ? n.toLocaleString() : BigInt(n).toLocaleString());

// --- Subnet calculator ---------------------------------------------------------------------

let snCurrent = null;

function snTiles(r) {
  const rows = [
    ["Network", `${r.network}<small>/${r.prefix}</small>`],
    ["Usable hosts", fmtInt(r.usable_hosts), `${fmtInt(r.total_addresses)} addresses in total`],
    ["First usable", r.first_usable],
    ["Last usable", r.last_usable],
    r.broadcast ? ["Broadcast", r.broadcast, "Reaches every device in the subnet"] : null,
    ["Netmask", r.netmask, `Wildcard ${r.wildcard}`],
    ["Address type", r.type, r.class ? `Class ${r.class} (historic)` : "IPv6"],
  ].filter(Boolean);
  return rows.map(([label, value, note]) => tile(label, value, note ? esc(note) : "", "small mono")).join("");
}

function snBinary(r) {
  if (r.version !== 4) {
    $("#sn-binary-card").hidden = false;
    $("#sn-binary").innerHTML = `<div class="bin-row"><span class="bin-label">Expanded</span><span class="mono">${esc(r.exploded)}</span></div>
      <div class="bin-row"><span class="bin-label">Compressed</span><span class="mono">${esc(r.compressed)}</span></div>`;
    $("#sn-binary-note").textContent = `The first ${r.prefix} of 128 bits identify the network; IPv6 has no broadcast address.`;
    return;
  }
  const colour = (bits) => {
    let i = 0;
    return bits.split("").map((c) => {
      if (c === ".") return '<span class="bin-dot">.</span>';
      const cls = i++ < r.binary.network_bits ? "bit-net" : "bit-host";
      return `<span class="${cls}">${c}</span>`;
    }).join("");
  };
  $("#sn-binary-card").hidden = false;
  $("#sn-binary").innerHTML = `
    <div class="bin-row"><span class="bin-label">Address</span><span class="mono">${colour(r.binary.address)}</span><span class="sub">${esc(r.address)}</span></div>
    <div class="bin-row"><span class="bin-label">Netmask</span><span class="mono">${colour(r.binary.netmask)}</span><span class="sub">${esc(r.netmask)}</span></div>`;
  const host = 32 - r.prefix;
  let note = `${r.prefix} network bits + ${host} host bits: 2^${host} = ${fmtInt(r.total_addresses)} addresses`;
  note += r.prefix < 31 ? ", minus the network and broadcast addresses." : r.prefix === 31 ? " (a point-to-point link: both are usable)." : " (a single host).";
  if (r.is_network_address) note += " Note: the address you entered is the network address itself, not a usable host.";
  if (r.is_broadcast_address) note += " Note: the address you entered is the broadcast address, not a usable host.";
  $("#sn-binary-note").textContent = note;
}

function snFillSplit(r) {
  const max = r.version === 4 ? 32 : Math.min(128, r.prefix + 16);
  const opts = [];
  for (let p = r.prefix + 1; p <= Math.min(max, r.prefix + 12); p++) {
    const count = 2 ** (p - r.prefix);
    opts.push(`<option value="${p}">/${p} (${fmtInt(count)} subnets)</option>`);
  }
  $("#sn-split-prefix").innerHTML = opts.join("") || `<option value="">Can't split a /${r.prefix}</option>`;
}

async function snCalculate(q) {
  const status = $("#sn-status");
  try {
    const r = await api(`/api/subnet?q=${encodeURIComponent(q)}`);
    snCurrent = r;
    setStatus(status, `${esc(r.address)} is in <b class="mono">${esc(r.cidr)}</b>.`);
    $("#sn-tiles").innerHTML = snTiles(r);
    snBinary(r);
    snFillSplit(r);
  } catch (err) {
    setStatus(status, esc(err.message), true);
  }
}

$("#sn-form").addEventListener("submit", (e) => { e.preventDefault(); snCalculate($("#sn-input").value); });
$("#sn-examples").addEventListener("click", (e) => {
  const ex = e.target.dataset?.ex;
  if (ex) { $("#sn-input").value = ex; snCalculate(ex); }
});
$("#sn-split-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!snCurrent || !$("#sn-split-prefix").value) return;
  try {
    const r = await api(`/api/subnet?q=${encodeURIComponent(snCurrent.cidr)}&split_prefix=${$("#sn-split-prefix").value}`);
    const s = r.split;
    $("#sn-split-note").textContent = `${s.parent} → ${fmtInt(s.count)} × /${s.new_prefix}` + (s.shown < s.count ? ` (showing the first ${s.shown})` : "");
    $("#sn-split-rows").innerHTML = s.subnets.map((n) => `<tr><td class="mono"><b>${esc(n.cidr)}</b></td>
      <td class="mono">${esc(n.first_usable)} – ${esc(n.last_usable)}</td><td class="mono">${esc(n.broadcast || "–")}</td>
      <td class="num">${fmtInt(n.usable_hosts)}</td></tr>`).join("");
  } catch (err) {
    $("#sn-split-note").textContent = err.message;
  }
});
$("#sn-sum-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const box = $("#sn-sum-result");
  try {
    const r = await api(`/api/subnet/summarize?q=${encodeURIComponent($("#sn-sum-input").value)}`);
    box.innerHTML = `<div><b>Fewest exact blocks:</b> ${r.collapsed.map((c) => `<span class="badge accent">${esc(c)}</span>`).join(" ")}</div>`
      + (r.supernet ? `<div class="top-gap-sm"><b>Single block covering all:</b> <span class="badge accent">${esc(r.supernet)}</span>
        <span class="sub">(may include addresses you didn't list)</span></div>` : "");
  } catch (err) {
    box.innerHTML = `<span class="t-critical">${esc(err.message)}</span>`;
  }
});

// Cheat sheet: every IPv4 prefix from /8 to /32.
(function snCheatSheet() {
  const uses = { 8: "Huge private network (10.0.0.0/8)", 12: "Private 172.16.0.0/12", 16: "Large site / campus", 22: "Big office or guest Wi-Fi",
    23: "Office", 24: "Typical home or small-office network", 25: "Half a /24", 26: "Department / VLAN", 27: "Small VLAN",
    28: "Server segment", 29: "Small block of public IPs", 30: "Router-to-router link (classic)", 31: "Point-to-point link (RFC 3021)", 32: "Single host / loopback" };
  const rows = [];
  for (let p = 8; p <= 32; p++) {
    const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
    const dotted = (v) => [24, 16, 8, 0].map((s) => (v >>> s) & 255).join(".");
    const total = 2 ** (32 - p);
    const usable = p === 32 ? 1 : p === 31 ? 2 : total - 2;
    rows.push(`<tr${p === 24 ? ' class="hl"' : ""}><td class="mono"><b>/${p}</b></td><td class="mono">${dotted(mask)}</td><td class="mono">${dotted(~mask >>> 0)}</td>
      <td class="num">${total.toLocaleString()}</td><td class="num">${usable.toLocaleString()}</td><td><span class="sub">${uses[p] || ""}</span></td></tr>`);
  }
  $("#sn-cheat").innerHTML = rows.join("");
})();
let snLoaded = false;
loaders.subnet = () => { if (!snLoaded) { snLoaded = true; snCalculate($("#sn-input").value); } };

// --- MAC vendor lookup --------------------------------------------------------------------------

async function macStatusLine() {
  try {
    const st = await api("/api/mac/status");
    setStatus($("#mac-status"), st.entries
      ? `Vendor database: ${st.entries.toLocaleString()} prefixes from ${esc(st.source)}.`
      : "No vendor database yet: install Nmap, or press <b>Update vendor database</b>.", !st.entries);
  } catch { /* ignore */ }
}
let macLoaded = false;
loaders.mac = () => { if (!macLoaded) { macLoaded = true; macStatusLine(); } };

function macCard(r) {
  if (!r.valid) return `<div class="card mac-card"><p class="t-critical">${esc(r.input)}: ${esc(r.error)}</p></div>`;
  const flags = [
    r.randomized && `<span class="badge accent">Private / randomized</span>`,
    r.multicast && !r.broadcast && `<span class="badge">Multicast</span>`,
    r.broadcast && `<span class="badge">Broadcast</span>`,
    !r.randomized && !r.multicast && `<span class="badge">Globally unique (factory)</span>`,
  ].filter(Boolean).join(" ");
  return `<div class="card mac-card">
    <div class="mac-head"><span class="mono mac-addr">${esc(r.mac)}</span>${flags}</div>
    <div class="mac-vendor">${r.vendor ? esc(r.vendor) : '<span class="sub">Unknown vendor</span>'}</div>
    <div class="sub">${r.vendor ? `Prefix ${esc(r.matched_prefix)} · ${esc(r.block)}` : `OUI ${esc(r.oui)}`}</div>
    ${r.note ? `<p class="sub top-gap-sm">${esc(r.note)}</p>` : ""}
  </div>`;
}

$("#mac-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const items = $("#mac-input").value.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean).slice(0, 50);
  if (!items.length) return;
  const results = await Promise.all(items.map((m) => api(`/api/mac?q=${encodeURIComponent(m)}`).catch((err) => ({ valid: false, input: m, error: err.message }))));
  $("#mac-results").innerHTML = `<div class="mac-grid">${results.map(macCard).join("")}</div>`;
});
$("#mac-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#mac-form").requestSubmit(); }
});
$("#mac-update").addEventListener("click", async () => {
  const btn = $("#mac-update");
  btn.disabled = true;
  setStatus($("#mac-status"), "Downloading the IEEE registry (about 6 MB)…");
  try {
    const st = await api("/api/mac/update", { method: "POST" });
    setStatus($("#mac-status"), `Updated: ${st.entries.toLocaleString()} prefixes from ${esc(st.source)}.`);
  } catch (err) {
    setStatus($("#mac-status"), `${esc(err.message)} The current database is still in use.`, true);
  }
  btn.disabled = false;
});

// --- Port reference -------------------------------------------------------------------------------

const PR_RISK = { ok: ["✔ Normal", "good"], caution: ["▲ Caution", "warning"], risky: ["✖ Risky", "critical"] };
let prData = null;

function prRender() {
  if (!prData) return;
  const q = $("#pr-q").value.trim().toLowerCase();
  const cat = $("#pr-cat").value;
  const risk = $("#pr-risk").value;
  const rows = prData.ports.filter((p) => {
    if (cat && p.category !== cat) return false;
    if (risk === "risky" && p.risk !== "risky") return false;
    if (risk === "caution" && p.risk === "ok") return false;
    if (!q) return true;
    if (/^\d+$/.test(q)) return String(p.port) === q;
    return `${p.name} ${p.description} ${p.note} ${p.category}`.toLowerCase().includes(q);
  });
  $("#pr-count").textContent = `${rows.length} of ${prData.total} ports`;
  $("#pr-rows").innerHTML = rows.map((p) => {
    const [label, tone] = PR_RISK[p.risk];
    return `<tr>
      <td class="num mono"><b>${p.port}</b></td><td class="mono">${esc(p.protocol)}</td>
      <td><b>${esc(p.name)}</b><span class="sub">${esc(p.category)}</span></td>
      <td>${esc(p.description)}${p.note ? `<span class="sub port-note">${esc(p.note)}</span>` : ""}</td>
      <td>${p.encrypted ? '<span class="t-good">🔒 Yes</span>' : '<span class="sub" style="display:inline">No</span>'}</td>
      <td><span class="t-${tone}">${label}</span></td></tr>`;
  }).join("") || `<tr><td colspan="6" class="empty">No matching ports. Try a number like 8080 or a word like "printer".</td></tr>`;
}
loaders.portref = async () => {
  if (prData) return;
  prData = await api("/api/portref");
  $("#pr-cat").insertAdjacentHTML("beforeend", prData.categories.map((c) => `<option>${esc(c)}</option>`).join(""));
  $("#pr-ranges").innerHTML = prData.ranges.map((r) => tile(esc(r.name), `<span class="mono">${r.range}</span>`, esc(r.description), "small")).join("");
  prRender();
};
["input", "change"].forEach((evt) => $("#pr-form").addEventListener(evt, prRender));
$("#pr-form").addEventListener("submit", (e) => e.preventDefault());

// --- DNS lookup ---------------------------------------------------------------------------------------

const DNS_STATUS = { none: "No records", nxdomain: "Name doesn't exist", timeout: "No answer (timed out)", error: "Lookup failed" };

function dnsTypeCard(type, res) {
  const head = `<div class="card-head"><h2>${esc(type)}</h2><span class="sub">${res.status === "ok"
    ? `TTL ${esc(res.ttl_human)}${res.ms != null ? ` · ${res.ms} ms` : ""}${res.via_cname ? ` · via alias ${esc(res.via_cname)}` : ""}`
    : esc(DNS_STATUS[res.status] || res.status)}</span></div>`;
  if (res.status !== "ok") return "";
  const body = res.records.map((r) => {
    let extra = "";
    if (r.spf) {
      extra = `<ul class="spf-terms">${r.spf.terms.map((t) => `<li><code>${esc(t.term)}</code> ${esc(t.explanation)}</li>`).join("")}</ul>`
        + `<p class="sub">${r.spf.lookups}/10 DNS lookups used</p>`;
    }
    if (r.dmarc) extra = `<ul class="spf-terms">${r.dmarc.lines.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
    if (r.details) extra = `<ul class="spf-terms">${r.details.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
    return `<div class="dns-rec">
      <div class="mono dns-val">${r.kind && r.kind !== "Text" ? `<span class="badge accent">${esc(r.kind)}</span> ` : ""}${esc(r.value)}</div>
      <div class="dns-exp">${esc(r.explanation || "")}</div>${extra}</div>`;
  }).join("");
  return `<div class="card">${head}${body}</div>`;
}

async function dnsLookup({ skipDumpster = false } = {}) {
  const q = $("#dns-q").value.trim();
  if (!q) return;
  const status = $("#dns-status");
  setStatus(status, `Looking up ${esc(q)}…`);
  $("#dns-radar").innerHTML = radarSVG(32);
  $("#dns-findings").innerHTML = $("#dns-results").innerHTML = "";
  try {
    const r = await api(`/api/dns?q=${encodeURIComponent(q)}&resolver=${$("#dns-resolver").value}`);
    if (r.kind === "ip") {
      setStatus(status, `Reverse lookup of ${esc(r.query)} (${esc(r.reverse_name)}) via ${esc(r.resolver)} in ${r.seconds}s.`);
      $("#dns-results").innerHTML = dnsTypeCard("PTR", r.results.PTR) || `<p class="sub">No reverse DNS name is registered for this address.</p>`;
    } else if (!r.exists) {
      setStatus(status, `${esc(r.query)} doesn't exist (NXDOMAIN): no such domain is registered, or it has no DNS.`, true);
    } else {
      const present = Object.entries(r.results).filter(([, v]) => v.status === "ok").map(([k]) => k);
      const missing = Object.entries(r.results).filter(([, v]) => v.status !== "ok").map(([k, v]) => `${k}: ${DNS_STATUS[v.status] || v.status}`);
      setStatus(status, `${esc(r.query)} via ${esc(r.resolver)} in ${r.seconds}s. Found ${present.join(", ") || "nothing"}.`);
      let extra = "";
      if (r.dmarc) {
        extra += dnsTypeCard(`DMARC (${r.dmarc.name})`, { status: "ok", ttl_human: "–", records: [{ value: r.dmarc.value, kind: "DMARC", explanation: "Policy for mail that fails SPF/DKIM checks.", dmarc: r.dmarc.parsed }] });
      }
      if (r.dkim_selectors?.length || r.dkim_note) {
        extra += `<div class="card"><div class="card-head"><h2>DKIM</h2></div><div class="dns-rec"><div class="dns-exp">${r.dkim_selectors?.length
          ? `Signing keys found at selector${r.dkim_selectors.length > 1 ? "s" : ""}: ${r.dkim_selectors.map((s) => `<code>${esc(s)}._domainkey</code>`).join(", ")}.`
          : esc(r.dkim_note)}</div></div></div>`;
      }
      $("#dns-results").innerHTML = `<div class="dns-grid">${present.map((t) => dnsTypeCard(t, r.results[t])).join("")}${extra}</div>`
        + (missing.length ? `<p class="sub top-gap-sm">Not present: ${esc(missing.join(" · "))}</p>` : "");
      $("#dns-findings").innerHTML = r.findings.length ? `<h2>What we noticed</h2>${r.findings.map(recCard).join("")}` : "";
      if (!skipDumpster && ddStatus?.configured && $("#dd-include").checked) ddLookup(r.query);
    }
  } catch (err) {
    setStatus(status, esc(err.message), true);
  }
  $("#dns-radar").innerHTML = "";
}
$("#dns-form").addEventListener("submit", (e) => { e.preventDefault(); dnsLookup(); });

let dnsLoaded = false;
loaders.dns = async () => {
  if (dnsLoaded) return;
  dnsLoaded = true;
  ddRefreshStatus();
  const data = await api("/api/dns/explainers");
  $("#dns-resolver").innerHTML = Object.entries(data.resolvers).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("");
  $("#dns-explainers").innerHTML = data.explainers.map((x) => `
    <details class="explainer">
      <summary><span class="badge accent">${esc(x.type)}</span> <b>${esc(x.title)}</b><span class="sub">${esc(x.summary)}</span></summary>
      <pre class="mono">${esc(x.example)}</pre>
      <p>${esc(x.details)}</p>
    </details>`).join("");
};


// --- DNSDumpster (hosts & subdomains) ------------------------------------------------------------------

let ddStatus = null;
let ddDomain = "";

function ddPref(value) {
  try {
    if (value === undefined) return localStorage.getItem("subnetry.dd-include") !== "0";
    localStorage.setItem("subnetry.dd-include", value ? "1" : "0");
  } catch { /* storage unavailable: default on */ }
  return true;
}

async function ddRefreshStatus() {
  try { ddStatus = await api("/api/dnsdumpster/status"); } catch { return; }
  const on = ddStatus.configured;
  $("#dd-setup").hidden = on;
  $("#dd-actions").hidden = !on;
  $("#dd-include").disabled = !on;
  $("#dd-include").checked = on && ddPref();
  $("#dd-key-state").innerHTML = on
    ? (ddStatus.source === "env" ? "API key from DNSDUMPSTER_API_KEY"
      : `API key ${esc(ddStatus.hint || "saved")} · <button class="link" type="button" id="dd-change">Change</button> · <button class="link" type="button" id="dd-remove">Remove</button>`)
    : "Not set up";
  if (!on && !$("#dd-results").innerHTML) setStatus($("#dd-status"), "");
}

async function ddLookup(domain) {
  domain = (domain || $("#dns-q").value).trim();
  if (!domain) { setStatus($("#dd-status"), "Enter a domain above first.", true); return; }
  ddDomain = domain;
  const status = $("#dd-status");
  setStatus(status, `Asking DNSDumpster about ${esc(domain)}…`);
  $("#dd-radar").innerHTML = radarSVG(28);
  $("#dd-results").innerHTML = "";
  $("#dd-run").disabled = true;
  try {
    const r = await api(`/api/dnsdumpster?q=${encodeURIComponent(domain)}`);
    if (domain !== ddDomain) return;  // a newer lookup started meanwhile
    const n = r.hosts.length;
    setStatus(status, `${n} record${n === 1 ? "" : "s"} for ${esc(r.domain)} · ${r.unique_ips} unique IP address${r.unique_ips === 1 ? "" : "es"}`
      + (r.cached ? ` · from ${esc(r.fetched_at)} (cached)` : ""));
    $("#dd-results").innerHTML = ddRender(r);
  } catch (err) {
    setStatus(status, esc(err.message), true);
    if (/rejected the API key/.test(err.message)) ddRefreshStatus();
  } finally {
    $("#dd-radar").innerHTML = "";
    $("#dd-run").disabled = false;
  }
}

function ddRender(r) {
  const counts = Object.entries(r.counts).filter(([, v]) => v).map(([k, v]) => `${k} ${v}`).join(" · ") || "none";
  const tiles = [
    tile("Hosts found", r.counts.A + r.counts.AAAA + r.counts.CNAME, esc(counts)),
    tile("Unique IPs", r.unique_ips),
    r.asns.length && tile("Main network", esc(r.asns[0][0]), r.asns.length > 1 ? `+ ${r.asns.length - 1} other${r.asns.length > 2 ? "s" : ""}` : "", "small"),
    r.countries.length && tile("Hosted in", esc(r.countries.map(([c]) => c).slice(0, 3).join(", ")), r.countries.length > 3 ? `+ ${r.countries.length - 3} more` : "", "small"),
  ].filter(Boolean).join("");
  const notable = r.notable.length ? recCard({
    severity: "info", category: "DNSDumpster", title: `${r.notable.length} host name${r.notable.length === 1 ? "" : "s"} worth a second look`,
    detail: `${r.notable.slice(0, 12).join(", ")}${r.notable.length > 12 ? "…" : ""}. Names like dev, test, staging, admin or vpn are often `
      + "forgotten or less protected than the main site, and anyone can find them this way.",
    action: "Check each one is still needed and properly secured (updates, login, HTTPS). Remove the DNS records of anything retired.",
  }) : "";
  const rows = r.hosts.flatMap((h) => (h.ips.length ? h.ips : [{}]).map((ip, i) => `<tr>
      <td><span class="badge${h.type === "MX" || h.type === "NS" ? "" : " accent"}">${esc(h.type)}</span></td>
      <td class="mono">${i ? "" : `<button class="link dd-host" type="button" data-host="${esc(h.host)}" title="Look up ${esc(h.host)}">${esc(h.host)}</button>`
        + (h.priority != null ? ` <span class="sub" style="display:inline">priority ${h.priority}</span>` : "")}</td>
      <td class="mono">${esc(ip.ip || "–")}</td>
      <td>${esc(ip.asn_name || "–")}${ip.asn ? `<span class="sub">AS${esc(ip.asn)}${ip.asn_range ? ` · ${esc(ip.asn_range)}` : ""}</span>` : ""}</td>
      <td>${esc(ip.country || "–")}</td>
      <td class="mono">${esc(ip.ptr || "–")}</td>
      <td>${ip.banners ? Object.entries(ip.banners).map(([p, b]) => `<span class="sub">${esc(p)}: ${esc(typeof b === "string" ? b
        : [b.server, b.title, b.cn].filter(Boolean).join(" · ") || Object.values(b).slice(0, 2).join(" · "))}</span>`).join("") : "–"}</td>
    </tr>`)).join("");
  const more = r.more_available
    ? `<p class="sub top-gap-sm">Showing ${r.shown_a} of ${r.total_a} A records. DNSDumpster's paid plan returns the rest.</p>` : "";
  const txt = r.txt.length ? `<details class="explainer top-gap-sm"><summary><b>TXT records (${r.txt.length})</b></summary>
      <ul class="spf-terms">${r.txt.map((t) => `<li><code>${esc(t)}</code></li>`).join("")}</ul></details>` : "";
  return `<div class="tiles top-gap-sm">${tiles}</div>${notable}
    <div class="table-wrap flat scroll-y tall top-gap-sm"><table>
      <thead><tr><th>Type</th><th>Host</th><th>IP address</th><th>Network (ASN)</th><th>Country</th><th>Reverse DNS</th><th>Services seen</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="empty">DNSDumpster has no host records for this domain.</td></tr>`}</tbody>
    </table></div>${more}${txt}`;
}

$("#dd-setup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const key = $("#dd-key").value.trim();
  if (!key) return;
  try {
    await api("/api/dnsdumpster/key", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) });
    $("#dd-key").value = "";
    ddPref(true);
    await ddRefreshStatus();
    setStatus($("#dd-status"), "API key saved. Look up a domain above, or press Search DNSDumpster.");
  } catch (err) {
    setStatus($("#dd-status"), esc(err.message), true);
  }
});
$("#dd-card").addEventListener("click", async (e) => {
  if (e.target.id === "dd-change") { $("#dd-setup").hidden = false; $("#dd-key").focus(); }
  if (e.target.id === "dd-remove") {
    await api("/api/dnsdumpster/key", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key: "" }) });
    $("#dd-results").innerHTML = "";
    await ddRefreshStatus();
    setStatus($("#dd-status"), "API key removed from this computer.");
  }
  if (e.target.classList.contains("dd-host")) {
    $("#dns-q").value = e.target.dataset.host;
    dnsLookup({ skipDumpster: true });  // one host's records; don't spend a DNSDumpster query on it
    $("#tab-dns").scrollIntoView({ behavior: "smooth" });
  }
});
$("#dd-run").addEventListener("click", () => ddLookup());
$("#dd-include").addEventListener("change", (e) => ddPref(e.target.checked));
