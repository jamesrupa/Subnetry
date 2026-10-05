"use strict";
// Traffic Analyzer: live tshark capture summarized as protocols, devices, destinations and insights.

const trSeries = { in: [], out: [] };
let trRun = null;
let trDuration = 60;
let trStatusLoaded = false;

async function loadTraffic() {
  if (trStatusLoaded) return;
  trStatusLoaded = true;
  drawTraffic();
  let st;
  try {
    st = await api("/api/traffic/status");
  } catch (err) {
    setStatus($("#tr-status"), esc(err.message), true);
    return;
  }
  if (!st.installed || st.error) {
    const box = $("#tr-missing");
    box.hidden = false;
    box.innerHTML = st.installed
      ? `<h2>Can't list capture interfaces</h2><p>${esc(st.error)}</p>`
      : `<h2>Wireshark (tshark) isn't installed</h2><p>${esc(st.install_help)}</p>`;
    $("#tr-start").disabled = true;
    if (!st.interfaces.length) return;
  }
  // Pre-select the interface carrying this machine's main network.
  const o = await loadOverview();
  const primary = o?.networks?.[0]?.interface?.toLowerCase();
  const skip = /^(any|lo|loopback|bluetooth|dbus|nflog|nfqueue|usbmon|ifb|dpauxmon|sdjournal|ciscodump|randpkt|sshdump|udpdump|wifidump|etwdump|androiddump)/i;
  const ifaces = st.interfaces.filter((i) => !skip.test(i.name) && !/loopback/i.test(i.description));
  const rest = st.interfaces.filter((i) => !ifaces.includes(i));
  const pick = ifaces.find((i) => primary && (i.name.toLowerCase() === primary || i.description.toLowerCase().includes(primary)))
    || ifaces.find((i) => /wi-?fi|wlan|wireless|ethernet|^en\d|^eth/i.test(`${i.name} ${i.description}`)) || ifaces[0];
  $("#tr-iface").innerHTML = [...ifaces, ...rest].map((i) =>
    `<option value="${esc(i.name)}" ${i === pick ? "selected" : ""}>${esc(i.description === i.name ? i.name : `${i.description}`)}</option>`).join("");
}
loaders.traffic = loadTraffic;

function drawTraffic() {
  lineChart($("#tr-chart"), [
    { name: "Download (in)", cls: "series-1", points: trSeries.in },
    { name: "Upload (out)", cls: "series-2", points: trSeries.out },
  ], { xMax: trDuration, xLabel: (x) => fmtT(x), yUnit: "Mbps" });
}

chartRedrawers.push(() => { if (!$("#tab-traffic").hidden) drawTraffic(); });

const hostName = (ip) => hosts.get(ip)?.hostname;  // from the Network Scanner, if it has been run

function renderTraffic(ev, live) {
  const devicesSeen = ev.devices.length;
  $("#tr-tiles").innerHTML = [
    tile("Packets", ev.packets.toLocaleString()),
    tile("Data captured", fmtBytes(ev.bytes)),
    tile("Local devices seen", devicesSeen),
    tile(live ? "Current rate" : "Average rate",
      live ? `${(ev.in_mbps + ev.out_mbps).toFixed(2)}<small>Mbps</small>` : `${((ev.bytes * 8) / 1e6 / Math.max(ev.seconds, 1)).toFixed(2)}<small>Mbps</small>`,
      live ? `↓ ${ev.in_mbps.toFixed(2)} · ↑ ${ev.out_mbps.toFixed(2)}` : ""),
  ].join("");

  const total = ev.protocols.reduce((a, p) => a + p.bytes, 0) || 1;
  $("#tr-protocols").innerHTML = ev.protocols.slice(0, 10).map((p) => {
    const pct = (100 * p.bytes) / total;
    return `<div class="row" title="${esc(p.description)}">
      <div class="name">${esc(p.label)}<span class="sub">${esc(p.description)}</span></div>
      <div class="track"><div class="fill" style="width:${Math.max(pct, 0.5)}%"></div></div>
      <div class="val">${pct < 1 ? "<1" : pct.toFixed(0)}% · ${fmtBytes(p.bytes)}</div></div>`;
  }).join("") || `<p class="sub">No packets yet.</p>`;

  $("#tr-insights").innerHTML = ev.insights.length ? ev.insights.map(recCard).join("") : `<p class="sub">Nothing unusual so far.</p>`;

  $("#tr-devices").innerHTML = ev.devices.map((d) => `<tr>
      <td class="mono">${esc(d.ip)}${hostName(d.ip) ? `<span class="sub">${esc(hostName(d.ip))}</span>` : ""}</td>
      <td class="num">${fmtBytes(d.sent)}</td><td class="num">${fmtBytes(d.received)}</td><td>${esc(d.top_protocol || "–")}</td></tr>`).join("")
    || `<tr><td colspan="4" class="empty">–</td></tr>`;

  $("#tr-dests").innerHTML = ev.destinations.map((d) => `<tr>
      <td>${d.name ? `<b>${esc(d.name)}</b><span class="sub mono">${esc(d.ips.join(", "))}</span>` : `<span class="mono">${esc(d.ips[0])}</span><span class="sub">No name seen</span>`}</td>
      <td>${esc(d.protocol)}</td><td class="num">${fmtBytes(d.bytes)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="empty">–</td></tr>`;

  const tags = { dns: ["Lookup", "info"], tls: ["Secure", "good"], warning: ["Plaintext", "warning"] };
  $("#tr-feed").innerHTML = ev.feed.map((f) => {
    const [label, cls] = tags[f.kind] || ["Event", "info"];
    return `<li><span class="when">${fmtT(f.t)}</span><span class="tag ${cls}">${label}</span><span>${esc(f.text)}</span></li>`;
  }).join("") || `<li class="sub">No lookups or connections yet.</li>`;
}

$("#tr-form").addEventListener("submit", (e) => {
  e.preventDefault();
  trDuration = Number($("#tr-duration").value);
  trSeries.in = []; trSeries.out = [];
  drawTraffic();
  const status = $("#tr-status");
  const params = new URLSearchParams({
    interface: $("#tr-iface").value, duration: trDuration, filter: $("#tr-filter").value, save: $("#tr-save").checked,
  });
  $("#tr-start").hidden = true;
  $("#tr-stop").hidden = false;
  setStatus(status, "Starting capture…");
  let failed = false;
  trRun = stream(`/api/traffic/capture?${params}`, (ev) => {
    if (ev.type === "start") setStatus(status, `Capturing on ${esc(ev.interface)} for ${fmtT(ev.duration)}${ev.filter ? ` (filter: ${esc(ev.filter)})` : ""}…`);
    if (ev.type === "stats") {
      trSeries.in.push({ x: ev.t, y: ev.in_mbps });
      trSeries.out.push({ x: ev.t, y: ev.out_mbps });
      drawTraffic();
      renderTraffic(ev, true);
      setStatus(status, `Capturing… ${fmtT(ev.t)} of ${fmtT(trDuration)}`);
    }
    if (ev.type === "done") {
      renderTraffic(ev, false);
      const saved = ev.pcap
        ? ` Saved to <span class="mono">${esc(ev.pcap_path)}</span>. <a href="/api/traffic/captures/${encodeURIComponent(ev.pcap)}" download>Download .pcapng</a> to open it in Wireshark.`
        : "";
      setStatus(status, `Capture finished: ${ev.packets.toLocaleString()} packets in ${ev.seconds}s.${saved}`);
    }
    if (ev.type === "error") { failed = true; setStatus(status, esc(ev.message), true); }
  }, (err) => {
    $("#tr-start").hidden = false;
    $("#tr-stop").hidden = true;
    trRun = null;
    if (err && !failed) setStatus(status, esc(err.message), true);
  });
});

$("#tr-stop").addEventListener("click", () => {
  trRun?.stop();
  setStatus($("#tr-status"), "Capture stopped. The results above cover what was captured so far.");
});

// --- Capture filter guide ---------------------------------------------------------------------------

/** Example filters, personalised with this computer's address, the router and the local network. */
function trFilterExamples(me, gw, lan) {
  return [
    ["Devices & addresses", [
      [`host ${gw}`, "Everything to or from your router"],
      [`host ${me}`, "Everything to or from this computer"],
      [`src host ${me}`, "Only what this computer sends (uploads)"],
      [`dst host ${me}`, "Only what this computer receives (downloads)"],
      [`net ${lan}`, "Traffic involving any device on your local network"],
      [`not net ${lan}`, "Only traffic to or from the internet"],
      ["ether host aa:bb:cc:dd:ee:ff", "One device by its MAC address (replace the example address)"],
    ]],
    ["Websites & apps", [
      ["tcp port 443", "Secure web traffic (HTTPS)"],
      ["tcp port 80", "Unencrypted web traffic (HTTP)"],
      ["port 80 or port 443", "All web traffic"],
      ["udp port 443", "QUIC / HTTP/3 (YouTube, Google and many apps)"],
      ["port 53", "DNS: every website name your devices look up"],
      ["tcp port 22", "SSH remote logins"],
      ["tcp port 3389", "Remote Desktop (RDP)"],
      ["tcp portrange 27015-27030 or udp portrange 27015-27030", "Steam games (example of a port range)"],
    ]],
    ["Local network chatter", [
      ["arp", "ARP: devices asking \"who has this IP address?\""],
      ["port 67 or port 68", "DHCP: devices getting an IP address when they join"],
      ["udp port 5353", "mDNS / Bonjour: AirPlay, printers, Chromecast announcing themselves"],
      ["udp port 1900", "SSDP / UPnP: smart TVs and media devices"],
      ["broadcast or multicast", "All broadcast and multicast traffic"],
      ["icmp", "Ping and network error messages"],
    ]],
    ["Cut the noise", [
      ["not port 443", "Everything except HTTPS (shows the less common traffic)"],
      ["not broadcast and not multicast", "Skip device announcements"],
      [`not host ${me}`, "Other devices only (needs a mirror port or monitor mode to see much)"],
      ["greater 1000", "Only large packets (bulk transfers, streaming)"],
      ["tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0", "Only new TCP connections being opened"],
    ]],
    ["Combining", [
      [`host ${me} and port 53`, "This computer's DNS lookups"],
      [`host ${gw} and not port 53`, "Talking to the router, apart from DNS"],
      [`src net ${lan} and dst port 443`, "Local devices opening HTTPS connections"],
      ["(port 80 or port 443) and not host 8.8.8.8", "Web traffic except to one address (use parentheses when mixing and/or)"],
      ["ip6", "IPv6 traffic only"],
    ]],
  ];
}

const TR_SYNTAX = [
  ["host <ip>", "Packets to or from an address", "host 192.168.1.20"],
  ["src / dst", "Restrict to the sender or the receiver", "src host 10.0.0.5"],
  ["net <cidr>", "A whole network", "net 192.168.1.0/24"],
  ["port <n>", "A TCP or UDP port", "port 53"],
  ["portrange <a>-<b>", "A range of ports", "portrange 6000-6010"],
  ["tcp / udp / icmp / arp", "A protocol (combine: tcp port 443)", "udp port 123"],
  ["ip / ip6", "IPv4 or IPv6 only", "ip6"],
  ["ether host <mac>", "A device by MAC address", "ether host 3c:22:fb:12:34:56"],
  ["broadcast / multicast", "Packets for everyone / a group", "not broadcast"],
  ["greater / less <bytes>", "Packet size", "less 128"],
  ["and / or / not", "Combine (also && || !)", "host 10.0.0.5 and not port 22"],
  ["( … )", "Group when mixing and/or", "(port 80 or port 443) and host 10.0.0.5"],
];

const TR_TRANSLATE = [
  ["ip.addr == 192.168.1.20", "host 192.168.1.20"],
  ["ip.src == 192.168.1.20", "src host 192.168.1.20"],
  ["ip.dst == 192.168.1.20", "dst host 192.168.1.20"],
  ["!(ip.addr == 192.168.1.20)", "not host 192.168.1.20"],
  ["ip.addr == 192.168.1.0/24", "net 192.168.1.0/24"],
  ["tcp.port == 443", "tcp port 443"],
  ["udp.port == 53 || tcp.port == 53", "port 53"],
  ["eth.addr == 3c:22:fb:12:34:56", "ether host 3c:22:fb:12:34:56"],
  ["dns", "port 53"],
  ["http", "tcp port 80"],
  ["tls", "tcp port 443"],
  ["dhcp", "port 67 or port 68"],
  ["arp / icmp / udp / tcp", "same: arp / icmp / udp / tcp"],
];

// Display-filter giveaways: field names like ip.addr, or ==/!= outside BPF byte expressions (tcp[13] == 2).
const TR_DISPLAY_SYNTAX = /\b(ip|ipv6|tcp|udp|eth|http|dns|tls|frame)\.[a-z]+/i;
const trLooksLikeDisplayFilter = (t) => TR_DISPLAY_SYNTAX.test(t) || (/==|!=/.test(t) && !t.includes("["));

/** Turn the most common Wireshark display filters into capture filters (null if not recognised). */
function trToCaptureFilter(text) {
  const t = text.trim();
  if (!trLooksLikeDisplayFilter(t)) return null;
  let out = t
    .replace(/!\s*\(\s*ip\.addr\s*==\s*([\w.:/]+)\s*\)/gi, "not host $1")
    .replace(/\bip\.(src|dst)\s*==\s*([\w.:/]+)/gi, (_, d, a) => `${d} ${a.includes("/") ? "net" : "host"} ${a}`)
    .replace(/\bip\.addr\s*==\s*([\w.:/]+)/gi, (_, a) => `${a.includes("/") ? "net" : "host"} ${a}`)
    .replace(/\b(tcp|udp)\.(src|dst)port\s*==\s*(\d+)/gi, "$1 $2 port $3")
    .replace(/\b(tcp|udp)\.port\s*==\s*(\d+)/gi, "$1 port $2")
    .replace(/\beth\.(src|dst)\s*==\s*([\w:]+)/gi, "ether $1 $2")
    .replace(/\beth\.addr\s*==\s*([\w:]+)/gi, "ether host $1")
    .replace(/\s*&&\s*/g, " and ").replace(/\s*\|\|\s*/g, " or ")
    .replace(/!\s*(?=[a-z(])/gi, "not ");
  return trLooksLikeDisplayFilter(out) ? null : out;
}

function trFilterHint() {
  const value = $("#tr-filter").value;
  const hint = $("#tr-filter-hint");
  const looksDisplay = trLooksLikeDisplayFilter(value) || /^\s*(http|dns|tls|dhcp|quic)\s*$/i.test(value);
  if (!looksDisplay) { hint.hidden = true; return; }
  const simple = { http: "tcp port 80", dns: "port 53", tls: "tcp port 443", dhcp: "port 67 or port 68", quic: "udp port 443" };
  const fixed = simple[value.trim().toLowerCase()] || trToCaptureFilter(value);
  hint.hidden = false;
  hint.innerHTML = `▲ This looks like a Wireshark <b>display</b> filter, which doesn't work for capturing. `
    + (fixed ? `Capture filter: <code>${esc(fixed)}</code> <button class="btn small" type="button" data-use="${esc(fixed)}">Use this</button>`
      : `Open <button class="link" type="button" data-open-help>Filter help</button> for the capture filter equivalent.`);
}

async function trOpenFilterHelp() {
  const o = await loadOverview().catch(() => null);
  const primary = o?.networks?.find((n) => n.interface === $("#tr-iface").value) || o?.networks?.[0];
  const me = primary?.address || "192.168.1.20";
  const lan = primary?.network || "192.168.1.0/24";
  const gw = o?.gateway || "192.168.1.1";
  const groups = trFilterExamples(me, gw, lan);
  $("#tr-help-examples").innerHTML = groups.map(([title, rows]) => `
    <section class="filter-group"><h3>${esc(title)}</h3>
      ${rows.map(([filter, what]) => `<div class="filter-example" data-text="${esc(`${title} ${filter} ${what}`.toLowerCase())}">
        <code>${esc(filter)}</code><span>${esc(what)}</span>
        <button class="btn small" type="button" data-use="${esc(filter)}">Use</button></div>`).join("")}
    </section>`).join("") + `<p class="sub empty" id="tr-help-none" hidden>No examples match. Try "port", "router" or "dns".</p>`;
  $("#tr-help-syntax").innerHTML = TR_SYNTAX.map(([w, m, ex]) =>
    `<tr><td><code>${esc(w)}</code></td><td>${esc(m)}</td><td><code>${esc(ex)}</code></td></tr>`).join("");
  $("#tr-help-translate").innerHTML = TR_TRANSLATE.map(([d, c]) =>
    `<tr><td><code>${esc(d)}</code></td><td><code>${esc(c)}</code></td></tr>`).join("");
  $("#tr-help-search").value = "";
  const dialog = $("#tr-help-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal(); else dialog.setAttribute("open", "");
  $("#tr-help-search").focus();
}

function trUseFilter(filter) {
  $("#tr-filter").value = filter;
  trFilterHint();
  const dialog = $("#tr-help-dialog");
  if (dialog.open) dialog.close();
  $("#tr-filter").focus();
}

$("#tr-filter-help").addEventListener("click", trOpenFilterHelp);
$("#tr-filter").addEventListener("input", trFilterHint);
$("#tr-filter-hint").addEventListener("click", (e) => {
  if (e.target.dataset.use) trUseFilter(e.target.dataset.use);
  if (e.target.hasAttribute("data-open-help")) trOpenFilterHelp();
});
$("#tr-help-dialog").addEventListener("click", (e) => {
  const dialog = e.currentTarget;
  if (e.target === dialog || e.target.hasAttribute("data-close")) dialog.close();  // backdrop or Close button
  if (e.target.dataset.use) trUseFilter(e.target.dataset.use);
});
$("#tr-help-search").addEventListener("input", (e) => {
  const words = e.target.value.toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;
  document.querySelectorAll("#tr-help-examples .filter-example").forEach((row) => {
    const match = words.every((w) => row.dataset.text.includes(w));
    row.hidden = !match;
    shown += match;
  });
  document.querySelectorAll("#tr-help-examples .filter-group").forEach((g) => {
    g.hidden = !g.querySelector(".filter-example:not([hidden])");
  });
  $("#tr-help-none").hidden = shown > 0;
});
