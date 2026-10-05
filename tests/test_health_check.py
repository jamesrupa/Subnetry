import asyncio
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from subnetry import server
from subnetry.tools import advisor, diagnose, report, traceroute, wifiscan


def titles(recs, severity=None):
    return [r["title"] for r in recs if severity is None or r["severity"] == severity]


# --- advisor rules -----------------------------------------------------------------

def test_speed_rules_thresholds():
    slow = advisor.speed_rules({"download_mbps": 8, "upload_mbps": 1.5, "latency_ms": 120, "jitter_ms": 40})
    assert {r["severity"] for r in slow} == {"critical", "warning"}
    assert any("Very slow download" in t for t in titles(slow, "critical"))
    assert any("High latency" in t for t in titles(slow, "critical"))
    assert any("High jitter" in t for t in titles(slow, "warning"))

    fast = advisor.speed_rules({"download_mbps": 450, "upload_mbps": 40, "latency_ms": 12, "jitter_ms": 2})
    assert [r["severity"] for r in fast] == ["good"]

    failed = advisor.speed_rules({"error": "ConnectError: unreachable"})
    assert failed[0]["severity"] == "critical" and "unreachable" in failed[0]["detail"]


@pytest.mark.parametrize("security,expected", [
    (None, "open"), ("Open", "open"), ("WEP", "wep"), ("WPA1", "wpa"), ("WPA2", "wpa2"),
    ("WPA1 WPA2", "wpa2"), ("WPA2-Personal / CCMP", "wpa2"), ("WPA2-Personal / TKIP", "wpa2-tkip"),
    ("WPA3", "wpa3"), ("WPA2 WPA3", "wpa3"), ("WPA3 Personal", "wpa3"),
])
def test_classify_security(security, expected):
    assert advisor.classify_security(security) == expected


def net(ssid, ch, dbm, sec="WPA2", in_use=False, band=None):
    return wifiscan.make_network(ssid, channel=ch, signal_dbm=dbm, security=sec, in_use=in_use, band=band)


def wifi_report(nets):
    return {"networks": nets, "channels": wifiscan.channel_report(nets)}


def test_wifi_rules_weak_open_crowded_24ghz_with_5ghz_available():
    nets = [
        net("Home", 6, -72, sec=None, in_use=True),
        net("Home", 44, -65),
        net("A", 6, -60), net("B", 5, -70), net("C", 8, -75), net("D", 1, -80),
    ]
    recs = advisor.wifi_rules(wifi_report(nets))
    assert any("Weak signal" in t for t in titles(recs, "warning"))
    assert any("not encrypted" in t for t in titles(recs, "critical"))
    assert any("5 GHz is available" in t for t in titles(recs, "warning"))
    change = next(r for r in recs if r["title"].startswith("Change Wi-Fi channel"))
    assert change["title"] == "Change Wi-Fi channel: 6 → 11 (2.4 GHz)" and "set the 2.4 GHz channel to 11" in change["action"]


def test_wifi_rules_off_grid_channel_and_good_5ghz():
    off = advisor.wifi_rules(wifi_report([net("Home", 3, -50, in_use=True)]))
    assert "Change Wi-Fi channel: 3 → 1 (2.4 GHz)" in titles(off, "warning")

    good = advisor.wifi_rules(wifi_report([net("Home", 149, -48, sec="WPA3", in_use=True), net("X", 36, -70)]))
    assert {r["severity"] for r in good} == {"good"}


def test_channel_rules_5ghz_switch_and_stay():
    busy = [net("Home", 36, -50, in_use=True), net("A", 36, -55), net("B", 40, -60), net("C", 44, -58)]
    change = next(r for r in advisor.wifi_rules(wifi_report(busy)) if r["title"].startswith("Change Wi-Fi channel"))
    assert change["title"] == "Change Wi-Fi channel: 36 → 149 (5 GHz)" and "non-DFS" in change["detail"]
    # Your own mesh nodes on the same channel aren't "neighbours".
    mesh = [net("Home", 149, -50, in_use=True), net("Home", 149, -60), net("A", 36, -70)]
    assert "Channel 149 is a good choice (5 GHz)" in titles(advisor.wifi_rules(wifi_report(mesh)), "good")


def test_channel_rules_dfs_and_6ghz():
    dfs = advisor.wifi_rules(wifi_report([net("Home", 100, -50, in_use=True)]))
    assert any("DFS" in t for t in titles(dfs, "info"))
    six = [net("Home", 37, -50, in_use=True, band="6 GHz"), net("A", 37, -52, band="6 GHz"), net("B", 33, -55, band="6 GHz")]
    change = next(r for r in advisor.wifi_rules(wifi_report(six)) if r["title"].startswith("Change Wi-Fi channel"))
    assert change["title"] == "Change Wi-Fi channel: 37 → 5 (6 GHz)" and "PSC" in change["detail"]
    also6 = advisor.wifi_rules(wifi_report([net("Home", 36, -50, in_use=True), net("Home", 37, -60, band="6 GHz")]))
    assert "Your router also offers 6 GHz" in titles(also6, "info")


def test_wifi_rules_unavailable_and_not_connected():
    assert advisor.wifi_rules({"error": "nmcli missing"})[0]["severity"] == "info"
    assert "Not connected" in advisor.wifi_rules(wifi_report([net("X", 1, -60)]))[0]["title"]


def test_network_rules_flags_risky_ports_and_router():
    network = {
        "network": "192.168.1.0/24", "gateway": "192.168.1.1",
        "hosts": [
            {"ip": "192.168.1.1", "is_gateway": True, "hostname": "router",
             "ports": {"open": [{"port": 80, "service": "HTTP"}, {"port": 5000, "service": "UPnP"}]}},
            {"ip": "192.168.1.20", "mac_randomized": True,
             "ports": {"open": [{"port": 23, "service": "Telnet"}, {"port": 3389, "service": "RDP"}]}},
            {"ip": "192.168.1.30", "ports": {"open": [{"port": 3389, "service": "RDP"}]}},
        ],
    }
    recs = advisor.network_rules(network, {})
    assert any("Telnet" in t for t in titles(recs, "critical"))
    rdp = next(r for r in recs if "RDP" in r["title"])
    assert "2 devices" in rdp["title"] and "192.168.1.30" in rdp["detail"]
    assert any("plain HTTP" in t for t in titles(recs, "warning"))
    assert any("UPnP" in t for t in titles(recs, "info"))
    assert any("3 devices" in t for t in titles(recs, "info"))


def test_recommend_sorts_and_scores():
    rep = {"speed": {"download_mbps": 8, "upload_mbps": 20, "latency_ms": 20, "jitter_ms": 1},
           "network": {"network": "10.0.0.0/24", "gateway": None, "hosts": []}}
    recs = advisor.recommend(rep)
    assert [r["severity"] for r in recs] == sorted((r["severity"] for r in recs), key=advisor.SEVERITY_ORDER.get)
    sc = advisor.score(recs)
    assert sc["value"] == 100 - 25 - 10 and sc["grade"] == "Fair"
    assert sc["counts"]["critical"] == 1 and sc["counts"]["warning"] == 1
    # one critical alone would score 75, but criticals cap the grade at Fair
    assert advisor.score([advisor.rec("critical", "Speed", "t", "d")])["grade"] == "Fair"


# --- orchestration (network tools stubbed) ------------------------------------------

@pytest.fixture
def stub_tools(monkeypatch):
    async def overview():
        return {"hostname": "pc", "os": "Test", "gateway": "192.168.1.1", "networks": [], "interfaces": [], "dns_servers": []}

    async def speedtest(**_):
        yield {"phase": "latency", "type": "start"}
        yield {"phase": "done", "type": "result", "latency_ms": 20.0, "jitter_ms": 2.0,
               "download_mbps": 300.0, "upload_mbps": 30.0}

    async def wifi():
        nets = [net("Home", 6, -55, in_use=True), net("Home", 36, -60)]
        return wifi_report(nets)

    async def scan_network(*_a, **_k):
        yield {"type": "start", "network": "192.168.1.0/24", "total": 254, "gateway": "192.168.1.1"}
        yield {"type": "host", "host": {"ip": "192.168.1.1", "is_gateway": True, "methods": ["icmp"], "open_ports": []}}
        yield {"type": "host", "host": {"ip": "192.168.1.9", "methods": ["tcp"], "open_ports": [23], "mac": "AA:BB:CC:00:11:22"}}
        yield {"type": "done", "network": "192.168.1.0/24", "hosts_found": 2, "seconds": 1.0}

    async def scan_ports(ip, **_):
        return {"host": ip, "scanned": 1, "seconds": 0, "open": [{"port": 23, "service": "Telnet"}] if ip.endswith(".9") else []}

    async def ookla_status():
        return {"installed": False}

    async def trace(target, max_hops=30, resolve=True):
        hops = [traceroute.summarize_hop({"hop": 1, "ips": ["192.168.1.1"], "rtts": [1.0, 1.2, 1.1], "notes": []}),
                traceroute.summarize_hop({"hop": 2, "ips": ["142.250.80.46"], "rtts": [12.0, 11.0, 13.0], "notes": []})]
        info = {"192.168.1.1": {"ip": "192.168.1.1", "scope": "local"},
                "142.250.80.46": {"ip": "142.250.80.46", "scope": "public", "asn": {"asn": "15169", "org": "Google LLC"}}}
        yield {"type": "start", "target": target, "max_hops": max_hops}
        for h in hops:
            yield {"type": "hop", "hop": h}
        yield {"type": "done", "target": target, "target_ip": "142.250.80.46", "hops": hops, "info": info,
               "path": traceroute.path_summary(hops, info),
               "findings": traceroute.findings(target, "142.250.80.46", hops, info), "seconds": 1.0}

    monkeypatch.setattr(diagnose.traceroute, "find_command", lambda: "/usr/sbin/traceroute")
    monkeypatch.setattr(diagnose.traceroute, "run", trace)
    monkeypatch.setattr(diagnose.ookla, "status", ookla_status)
    monkeypatch.setattr(diagnose.nmapscan, "find_nmap", lambda: None)
    monkeypatch.setattr(diagnose.netinfo, "overview", overview)
    monkeypatch.setattr(diagnose.speedtest, "run_speedtest", speedtest)
    monkeypatch.setattr(diagnose.wifiscan, "scan_wifi", wifi)
    monkeypatch.setattr(diagnose.netscan, "scan_network", scan_network)
    monkeypatch.setattr(diagnose.netscan, "scan_ports", scan_ports)


async def run(mode):
    return [ev async for ev in diagnose.run_diagnosis(mode)]


def test_quick_scan_runs_speed_and_wifi(stub_tools):
    events = asyncio.run(run("quick"))
    assert events[0]["type"] == "plan" and [s["id"] for s in events[0]["steps"]] == ["speed", "wifi"]
    rep = events[-1]["report"]
    assert rep["speed"]["download_mbps"] == 300.0 and rep["speed"]["engine_id"] == "cloudflare"
    assert rep["wifi"]["networks"] and "network" not in rep
    # Cloudflare was used because the Ookla CLI is missing: say so, without costing points.
    assert "Measured with Cloudflare (Speedtest.net CLI not installed)" in titles(rep["recommendations"], "info")
    assert any(r["category"] == "Wi-Fi" for r in rep["recommendations"])
    assert rep["score"]["value"] == advisor.score(rep["recommendations"])["value"]


def test_full_scan_combines_everything(stub_tools):
    events = asyncio.run(run("full"))
    assert [s["id"] for s in events[0]["steps"]] == ["speed", "trace", "devices", "ports", "wifi"]
    statuses = [(e["step"], e["status"]) for e in events if e["type"] == "step" and e["status"] != "running"]
    assert statuses == [("speed", "done"), ("trace", "done"), ("devices", "done"), ("ports", "done"), ("wifi", "done")]
    rep = events[-1]["report"]
    assert [h["ip"] for h in rep["network"]["hosts"]] == ["192.168.1.1", "192.168.1.9"]
    assert rep["network"]["hosts"][1]["ports"]["open"][0]["port"] == 23
    assert rep["port_scan"]["engine"] == "built-in" and rep["port_scan"]["ports"] == 1000
    assert any("Telnet" in r["title"] for r in rep["recommendations"])
    assert rep["score"]["value"] < 100
    top = rep["score"]["improvements"][0]
    assert "Telnet" in top["title"] and top["points"] > 0 and top["action"]


def test_full_scan_traces_to_google(stub_tools):
    rep = asyncio.run(run("full"))[-1]["report"]
    assert rep["trace"]["target"] == "google.com" and len(rep["trace"]["hops"]) == 2
    assert [p["name"] for p in rep["trace"]["path"]] == ["your network", "Google LLC"]
    titles_ = titles(rep["recommendations"])
    assert "Reached google.com in 2 hops" in titles_ and "Your router answers quickly (1.1 ms)" in titles_
    html = report.render(rep, "html")
    assert "<h2>Traceroute to google.com</h2>" in html and "Your network → Google LLC" in html
    assert "trace" not in [s["id"] for s in asyncio.run(run("quick"))[0]["steps"]]


def test_full_scan_without_traceroute(stub_tools, monkeypatch):
    monkeypatch.setattr(diagnose.traceroute, "find_command", lambda: None)
    events = asyncio.run(run("full"))
    rep = events[-1]["report"]
    assert "isn't available" in rep["trace"]["error"]
    assert "Traceroute unavailable" in titles(rep["recommendations"], "info")
    assert "<h2>Traceroute</h2><p class='muted'>traceroute isn&#x27;t available" in report.render(rep, "html")


def test_full_scan_uses_top_1000_ports(stub_tools, monkeypatch):
    seen = {}

    async def scan_ports(ip, ports=None, **_):
        seen[ip] = ports
        return {"host": ip, "scanned": len(ports), "seconds": 0, "open": []}

    monkeypatch.setattr(diagnose.netscan, "scan_ports", scan_ports)
    rep = asyncio.run(run("full"))[-1]["report"]
    assert all(len(p) == 1000 and p[:3] == [80, 23, 443] for p in seen.values())
    assert "No risky services found" in titles(rep["recommendations"], "good")


def test_full_scan_prefers_nmap(stub_tools, monkeypatch):
    calls = []

    async def scan_hosts_top_ports(ips):
        calls.append(ips)
        yield {"type": "progress", "task": "Connect Scan", "percent": 50.0}
        yield {"type": "result", "result": {"hosts": [
            {"ip": "192.168.1.9", "vendor": "Acme", "ports": [
                {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql"},
                {"port": 9, "protocol": "tcp", "state": "open|filtered", "service": "discard"}]},
        ]}}

    async def must_not_run(*_a, **_k):
        raise AssertionError("built-in scanner used although nmap is available")

    monkeypatch.setattr(diagnose.nmapscan, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(diagnose.nmapscan, "scan_hosts_top_ports", scan_hosts_top_ports)
    monkeypatch.setattr(diagnose.netscan, "scan_ports", must_not_run)
    events = asyncio.run(run("full"))
    rep = events[-1]["report"]
    assert calls == [["192.168.1.1", "192.168.1.9"]] and rep["port_scan"]["engine"] == "nmap"
    host = rep["network"]["hosts"][1]
    assert host["ports"]["open"] == [{"port": 3306, "service": "mysql"}] and host["vendor"] == "Acme"
    assert rep["network"]["hosts"][0]["ports"]["open"] == []
    assert any(e["event"].get("type") == "progress" for e in events if e["type"] == "step_event" and e["step"] == "ports")
    # MySQL isn't in the built-in risky list, but the port reference marks it risky.
    assert any("MySQL" in t and "port 3306" in t for t in titles(rep["recommendations"], "warning"))


def test_nmap_failure_falls_back_to_builtin(stub_tools, monkeypatch):
    async def broken(ips):
        raise diagnose.netscan.ScanError("nmap exited with code 1")
        yield  # pragma: no cover

    monkeypatch.setattr(diagnose.nmapscan, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(diagnose.nmapscan, "scan_hosts_top_ports", broken)
    events = asyncio.run(run("full"))
    notices = [e["event"]["message"] for e in events if e["type"] == "step_event" and e["event"].get("type") == "notice"]
    assert notices and "built-in" in notices[0]
    assert events[-1]["report"]["port_scan"]["engine"] == "built-in"


def test_speed_prefers_ookla_and_falls_back(stub_tools, monkeypatch):
    from subnetry.tools import ookla

    async def installed():
        return {"installed": True}

    async def ookla_ok(server_id=None):
        yield {"phase": "done", "type": "result", "latency_ms": 9.0, "jitter_ms": 1.0,
               "download_mbps": 900.0, "upload_mbps": 80.0, "engine": "Speedtest.net (Ookla)"}

    async def ookla_broken(server_id=None):
        yield {"phase": "error", "type": "error", "message": "No servers available"}

    monkeypatch.setattr(diagnose.ookla, "status", installed)
    monkeypatch.setattr(ookla, "run", ookla_ok)
    rep = asyncio.run(run("quick"))[-1]["report"]
    assert rep["speed"]["engine_id"] == "ookla" and rep["speed"]["download_mbps"] == 900.0
    assert not any("Cloudflare" in t for t in titles(rep["recommendations"]))

    monkeypatch.setattr(ookla, "run", ookla_broken)
    events = asyncio.run(run("quick"))
    rep = events[-1]["report"]
    assert rep["speed"]["engine_id"] == "cloudflare" and rep["speed"]["download_mbps"] == 300.0
    assert rep["speed"]["fallback_reason"] == "No servers available"
    assert "Measured with Cloudflare (Speedtest.net didn't finish)" in titles(rep["recommendations"], "info")
    assert any(e["event"].get("type") == "fallback" for e in events if e["type"] == "step_event")


def test_improvements_rank_by_points():
    recs = [advisor.rec("warning", "Wi-Fi", "Weak signal", "d", "Move closer"),
            advisor.rec("critical", "Security", "Telnet open", "d", "Disable Telnet"),
            advisor.rec("good", "Speed", "Fast", "d")]
    plan = advisor.score(recs)["improvements"]
    assert [p["title"] for p in plan] == ["Telnet open", "Weak signal"]
    # 65 now. Fixing Telnet: 90. Fixing only the weak signal: 75, but a remaining critical caps it at 74, so +9.
    assert plan[0]["points"] == 25 and plan[1]["points"] == 9 and plan[0]["action"] == "Disable Telnet"


def test_failing_step_does_not_abort(stub_tools, monkeypatch):
    async def broken():
        raise RuntimeError("radio exploded")
    monkeypatch.setattr(diagnose.wifiscan, "scan_wifi", broken)
    events = asyncio.run(run("full"))
    assert ("wifi", "error") in [(e["step"], e["status"]) for e in events if e["type"] == "step"]
    rep = events[-1]["report"]
    assert rep["errors"]["wifi"] == "radio exploded" and "network" in rep


# --- export & API -------------------------------------------------------------------

def test_exports_render(stub_tools):
    rep = asyncio.run(run("full"))[-1]["report"]
    html = report.render(rep, "html")
    assert "<h2>Recommendations</h2>" in html and "Telnet" in html and "192.168.1.9" in html
    assert json.loads(report.render(rep, "json"))["id"] == rep["id"]
    devices = list(csv.DictReader(io.StringIO(report.render(rep, "devices.csv"))))
    assert devices[0]["role"] == "gateway" and devices[1]["open_ports"] == "23/Telnet"
    wifi_rows = list(csv.DictReader(io.StringIO(report.render(rep, "wifi.csv"))))
    assert wifi_rows[0]["connected"] == "yes"
    recs = list(csv.DictReader(io.StringIO(report.render(rep, "recommendations.csv"))))
    assert recs[0]["severity"] == "critical"


def test_html_escapes_untrusted_names():
    rep = {"id": "x", "mode": "full", "recommendations": [], "score": {},
           "wifi": wifi_report([net("<script>alert(1)</script>", 1, -50, in_use=True)])}
    assert "<script>alert" not in report.to_html(rep)


def test_api_full_scan_saves_and_exports(stub_tools, monkeypatch, tmp_path):
    monkeypatch.setenv("SUBNETRY_REPORTS_DIR", str(tmp_path))
    client = TestClient(server.app)
    with client.stream("GET", "/api/diagnose", params={"mode": "full"}) as r:
        body = r.read().decode()
    events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith('data: {"')]
    rep = events[-1]["report"]
    assert len(rep["saved_files"]) == 4
    names = sorted(p.name.split(".", 1)[1] for p in tmp_path.iterdir() if not p.name.startswith("."))
    assert names == ["devices.csv", "html", "json", "wifi.csv"]
    saved = next(p for p in tmp_path.iterdir() if p.name.endswith(".devices.csv")).read_text()
    assert "192.168.1.9" in saved and "23/Telnet" in saved

    r = client.get(f"/api/reports/{rep['id']}/export", params={"format": "devices.csv"})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert r.headers["content-disposition"].endswith('.devices.csv"')
    assert client.get(f"/api/reports/{rep['id']}/export", params={"format": "exe"}).status_code == 400
    assert client.get("/api/reports/nope/export").status_code == 404
    assert client.get("/api/diagnose", params={"mode": "bogus"}).status_code == 422


def test_quick_scan_is_not_saved(stub_tools, monkeypatch, tmp_path):
    monkeypatch.setenv("SUBNETRY_REPORTS_DIR", str(tmp_path))
    client = TestClient(server.app)
    with client.stream("GET", "/api/diagnose", params={"mode": "quick"}) as r:
        body = r.read().decode()
    assert "saved_files" not in body and not [p for p in tmp_path.iterdir() if not p.name.startswith(".")]
