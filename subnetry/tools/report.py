"""Export a health-check report as standalone HTML, JSON or CSV, and save it to disk."""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime
from html import escape
from pathlib import Path

SEVERITY_LABEL = {"critical": "Critical", "warning": "Warning", "info": "Info", "good": "Good"}
SEVERITY_ICON = {"critical": "✖", "warning": "▲", "info": "ℹ", "good": "✔"}

EXPORTS = {
    "html": ("text/html", "html"),
    "json": ("application/json", "json"),
    "recommendations.csv": ("text/csv", "recommendations.csv"),
    "devices.csv": ("text/csv", "devices.csv"),
    "wifi.csv": ("text/csv", "wifi.csv"),
}


# Saved automatically after every full scan: the report plus the device list (with open ports) and Wi-Fi list.
FULL_SCAN_FILES = ("html", "json", "devices.csv", "wifi.csv")

LEGACY_REPORTS_DIR = "NetApp-Reports"  # the app's previous name


def reports_dir() -> Path:
    custom = os.environ.get("SUBNETRY_REPORTS_DIR") or os.environ.get("NETAPP_REPORTS_DIR")
    if custom:
        return Path(custom)
    folder = Path.home() / "Subnetry-Reports"
    legacy = Path.home() / LEGACY_REPORTS_DIR
    if not folder.exists() and legacy.is_dir():
        try:
            legacy.rename(folder)  # one-time move of reports saved under the old name
        except OSError:
            return legacy
    return folder


def filename(report: dict, ext: str) -> str:
    return f"subnetry-{report['mode']}-scan-{report['id']}.{ext}"


def _local_time(iso: str | None) -> str:
    if not iso:
        return "–"
    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")


# --- CSV --------------------------------------------------------------------------

def _csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def recommendations_csv(report: dict) -> str:
    return _csv(["severity", "category", "title", "detail", "action"],
                [[r["severity"], r["category"], r["title"], r["detail"], r["action"]]
                 for r in report.get("recommendations", [])])


def devices_csv(report: dict) -> str:
    rows = []
    for h in (report.get("network") or {}).get("hosts", []):
        role = "gateway" if h.get("is_gateway") else "this device" if h.get("is_self") else ""
        ports = (h.get("ports") or {}).get("open")
        rows.append([
            h["ip"], h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or "",
            "yes" if h.get("mac_randomized") else "",
            role, "+".join(h.get("methods", [])), h.get("rtt_ms") if h.get("rtt_ms") is not None else "",
            " ".join(f"{p['port']}/{p['service']}" for p in ports) if ports is not None else "not scanned",
        ])
    return _csv(["ip", "hostname", "mac", "vendor", "randomized_mac", "role", "detected_by", "response_ms", "open_ports"], rows)


def wifi_csv(report: dict) -> str:
    rows = [[n["ssid"], n.get("bssid") or "", n.get("signal_dbm"), n.get("signal_percent"), n.get("channel"),
             n.get("band"), n.get("security"), "yes" if n.get("in_use") else ""]
            for n in (report.get("wifi") or {}).get("networks", [])]
    return _csv(["ssid", "bssid", "signal_dbm", "signal_percent", "channel", "band", "security", "connected"], rows)


# --- HTML -------------------------------------------------------------------------

CSS = """
:root { --text:#0b0b0b; --muted:#5d5c58; --border:#dcdbd6; --bg:#fcfcfb; --soft:#f1f1ee;
        --accent:#2a78d6; --good:#0e7a3a; --warning:#a86a00; --critical:#c22f2e; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:960px; margin:0 auto; padding:32px 24px 48px; }
h1 { font-size:24px; margin:0; } h2 { font-size:17px; margin:32px 0 10px; border-bottom:1px solid var(--border); padding-bottom:6px; }
.muted { color:var(--muted); }
.mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-top:18px; }
.tile { border:1px solid var(--border); border-radius:10px; padding:12px 14px; }
.tile .l { color:var(--muted); font-size:12px; } .tile .v { font-size:24px; font-weight:650; }
.tile .v small { font-size:12px; color:var(--muted); font-weight:400; margin-left:3px; }
.rec { border:1px solid var(--border); border-left:4px solid var(--muted); border-radius:8px; padding:10px 14px; margin:8px 0; break-inside:avoid; }
.rec.critical { border-left-color:var(--critical); } .rec.warning { border-left-color:var(--warning); }
.rec.info { border-left-color:var(--accent); } .rec.good { border-left-color:var(--good); }
.rec .sev { font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }
.critical .sev { color:var(--critical); } .warning .sev { color:var(--warning); } .info .sev { color:var(--accent); } .good .sev { color:var(--good); }
.rec h3 { font-size:15px; margin:2px 0; } .rec p { margin:4px 0; }
.rec .action { background:var(--soft); border-radius:6px; padding:6px 10px; }
.improve { padding-left:20px; } .improve li { margin:6px 0; break-inside:avoid; } .improve b { color:var(--good, #047857); margin-right:6px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
th { background:var(--soft); font-size:12px; color:var(--muted); }
td.num { text-align:right; font-variant-numeric:tabular-nums; }
.bars td { padding:3px 8px; } .bar { height:12px; background:var(--accent); border-radius:0 3px 3px 0; min-width:2px; }
@media print { main { padding:0; } h2 { break-after:avoid; } }
"""


def _speed_html(speed: dict | None) -> str:
    if not speed:
        return ""
    if speed.get("error"):
        return f"<h2>Speed test</h2><p class='muted'>Failed: {escape(speed['error'])}</p>"
    tiles = [("Download", speed.get("download_mbps"), "Mbps"), ("Upload", speed.get("upload_mbps"), "Mbps"),
             ("Ping", speed.get("latency_ms"), "ms"), ("Jitter", speed.get("jitter_ms"), "ms")]
    if speed.get("packet_loss") is not None:
        tiles.append(("Packet loss", speed["packet_loss"], "%"))
    srv = speed.get("server") or {}
    parts = (speed.get("engine"), srv.get("name"), srv.get("location"), speed.get("isp"))
    where = " · ".join(escape(str(x)) for x in dict.fromkeys(x for x in parts if x))  # no "Cloudflare · Cloudflare"
    link = f" · <a href='{escape(speed['result_url'])}'>speedtest.net result</a>" if speed.get("result_url") else ""
    return f"<h2>Speed test</h2><p class='muted'>{where}{link}</p><div class='tiles'>" + "".join(
        f"<div class='tile'><div class='l'>{label}</div><div class='v'>{'–' if v is None else f'{v:g}'}<small>{unit}</small></div></div>"
        for label, v, unit in tiles) + "</div>"


def _wifi_html(wifi: dict | None) -> str:
    if wifi is None:
        return ""
    if wifi.get("error"):
        return f"<h2>Wi-Fi</h2><p class='muted'>{escape(wifi['error'])}</p>"
    nets = wifi.get("networks", [])
    rows = "".join(
        f"<tr><td>{escape(n['ssid'] or '(hidden)')}{' <b>(connected)</b>' if n.get('in_use') else ''}</td>"
        f"<td class='mono'>{escape(n.get('bssid') or '–')}</td><td class='num'>{n.get('signal_dbm') if n.get('signal_dbm') is not None else '–'} dBm</td>"
        f"<td class='num'>{n.get('channel') or '–'}</td><td>{escape(n.get('band') or '–')}</td><td>{escape(n.get('security') or '')}</td></tr>"
        for n in nets)
    usage = wifi.get("channels", {}).get("usage", {})
    charts = ""
    for band, chans in sorted(usage.items()):
        top = max(chans.values()) if chans else 1
        bars = "".join(
            f"<tr><td class='num' style='width:70px'>ch {ch}</td><td><div class='bar' style='width:{100 * c / top:.0f}%'></div></td>"
            f"<td class='num' style='width:50px'>{c}</td></tr>" for ch, c in chans.items())
        charts += f"<h3 style='font-size:14px;margin:16px 0 4px'>{escape(band)}: networks per channel</h3><table class='bars'>{bars}</table>"
    return (f"<h2>Wi-Fi ({len(nets)} access points)</h2>{charts}"
            "<table style='margin-top:14px'><thead><tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Channel</th><th>Band</th>"
            f"<th>Security</th></tr></thead><tbody>{rows}</tbody></table>")


def _improve_html(score: dict) -> str:
    plan = score.get("improvements") or []
    if not plan:
        return ""
    items = "".join(f"<li><b>+{p['points']}</b> {escape(p['title'])}<br><span class='muted'>{escape(p['action'])}</span></li>"
                    for p in plan)
    return f"<h2>How to improve your score</h2><ol class='improve'>{items}</ol>"


def _devices_html(network: dict | None, port_scan: dict | None = None) -> str:
    if network is None:
        return ""
    if network.get("error"):
        return f"<h2>Devices</h2><p class='muted'>{escape(network['error'])}</p>"
    hosts = network.get("hosts", [])
    rows = []
    for h in hosts:
        role = " <b>(router)</b>" if h.get("is_gateway") else " <b>(this device)</b>" if h.get("is_self") else ""
        ports = (h.get("ports") or {}).get("open")
        port_txt = ", ".join(f"{p['port']} {escape(p['service'])}" for p in ports) if ports else ("none" if ports is not None else "–")
        mac = escape(h.get("mac") or "–") + (" <span class='muted'>(private)</span>" if h.get("mac_randomized") else "")
        rows.append(f"<tr><td class='mono'>{escape(h['ip'])}{role}</td><td>{escape(h.get('hostname') or '–')}</td>"
                    f"<td class='mono'>{mac}</td><td>{escape(h.get('vendor') or '–')}</td><td>{port_txt}</td></tr>")
    scan_note = ""
    if port_scan and port_scan.get("engine"):
        engine = "Nmap" if port_scan["engine"] == "nmap" else "Subnetry's built-in scanner"
        scan_note = (f"<p class='muted'>Port scan: the {port_scan['ports']} most common TCP ports on each device, "
                     f"with {engine}" + (f", in {port_scan['seconds']} s" if port_scan.get("seconds") is not None else "") + ".</p>")
    return (f"<h2>Devices on {escape(str(network.get('network', '')))} ({len(hosts)})</h2>{scan_note}"
            "<table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Open ports</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def to_html(report: dict) -> str:
    sys = report.get("system", {})
    sc = report.get("score", {})
    recs = "".join(
        f"<div class='rec {r['severity']}'><div class='sev'>{SEVERITY_ICON[r['severity']]} {SEVERITY_LABEL[r['severity']]} · "
        f"{escape(r['category'])}</div><h3>{escape(r['title'])}</h3><p>{escape(r['detail'])}</p>"
        + (f"<p class='action'><b>Recommended change:</b> {escape(r['action'])}</p>" if r["action"] else "")
        + "</div>" for r in report.get("recommendations", []))
    counts = sc.get("counts", {})
    title = f"Subnetry {report['mode'].title()} Scan"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} – {_local_time(report.get('started_at'))}</title><style>{CSS}</style></head>
<body><main>
<h1>{title} report</h1>
<p class="muted">{_local_time(report.get('started_at'))} · {escape(sys.get('hostname', ''))} ({escape(sys.get('os', ''))}) ·
gateway {escape(sys.get('gateway') or '–')} · took {report.get('duration_s', '–')} s</p>
<div class="tiles">
  <div class="tile"><div class="l">Health score</div><div class="v">{sc.get('value', '–')}<small>/ 100 · {escape(sc.get('grade', ''))}</small></div></div>
  <div class="tile"><div class="l">Critical</div><div class="v">{counts.get('critical', 0)}</div></div>
  <div class="tile"><div class="l">Warnings</div><div class="v">{counts.get('warning', 0)}</div></div>
  <div class="tile"><div class="l">Looks good</div><div class="v">{counts.get('good', 0)}</div></div>
</div>
{_improve_html(sc)}
<h2>Recommendations</h2>{recs or "<p class='muted'>No recommendations.</p>"}
{_speed_html(report.get('speed'))}
{_wifi_html(report.get('wifi'))}
{_devices_html(report.get('network'), report.get('port_scan'))}
<p class="muted" style="margin-top:32px">Generated by Subnetry. Report ID {escape(report['id'])}.</p>
</main></body></html>"""


# --- dispatch & save ----------------------------------------------------------------

def render(report: dict, fmt: str) -> str:
    if fmt == "html":
        return to_html(report)
    if fmt == "json":
        return json.dumps(report, indent=2)
    if fmt == "recommendations.csv":
        return recommendations_csv(report)
    if fmt == "devices.csv":
        return devices_csv(report)
    if fmt == "wifi.csv":
        return wifi_csv(report)
    raise ValueError(f"Unknown export format: {fmt}")


def save(report: dict, formats: tuple[str, ...] = ("html", "json")) -> list[str]:
    """Write the report to the reports folder; returns the file paths."""
    folder = reports_dir()
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        path = folder / filename(report, EXPORTS[fmt][1])
        path.write_text(render(report, fmt), encoding="utf-8")
        paths.append(str(path))
    return paths
