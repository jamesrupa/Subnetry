"""Traceroute: parsers for macOS/Linux and Windows output, analysis, and the live stream."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from subnetry.server import app
from subnetry.tools import traceroute

MAC_OUTPUT = """\
 1  192.168.1.1  2.912 ms  1.879 ms  1.654 ms
 2  100.92.0.1  9.512 ms  10.022 ms  8.844 ms
 3  * * *
 4  68.86.90.1  12.311 ms
    68.86.90.5  13.402 ms  12.998 ms
 5  142.250.80.46  95.1 ms !H  94.7 ms  96.0 ms
"""
MAC_HEADER = "traceroute to google.com (142.250.80.46), 64 hops max, 52 byte packets"

WINDOWS_OUTPUT = """\

Tracing route to google.com [142.250.80.46]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     9 ms     *       10 ms  100.92.0.1
  3     *        *        *     Request timed out.
  4    12 ms    13 ms    12 ms  68.86.90.1
  5    95 ms    94 ms    96 ms  142.250.80.46

Trace complete.
"""


def test_parse_unix_lines():
    assert traceroute.parse_header(MAC_HEADER) == {"name": "google.com", "ip": "142.250.80.46"}
    lines = [traceroute.parse_unix_line(l) for l in MAC_OUTPUT.splitlines()]
    assert lines[0] == {"hop": 1, "ips": ["192.168.1.1"], "rtts": [2.912, 1.879, 1.654], "notes": []}
    assert lines[2] == {"hop": 3, "ips": [], "rtts": [None, None, None], "notes": []}
    assert lines[3]["ips"] == ["68.86.90.1"] and lines[3]["rtts"] == [12.311]
    assert lines[4] == {"hop": None, "ips": ["68.86.90.5"], "rtts": [13.402, 12.998], "notes": []}  # continuation
    assert lines[5]["notes"] == ["!H"] and lines[5]["rtts"] == [95.1, 94.7, 96.0]
    multi = traceroute.parse_unix_line(" 7  10.0.0.1  9.8 ms 10.0.0.2  11.2 ms  *")
    assert multi["ips"] == ["10.0.0.1", "10.0.0.2"] and multi["rtts"] == [9.8, 11.2, None]
    v6 = traceroute.parse_unix_line(" 2  2001:db8::1  5.1 ms  4.9 ms  5.0 ms")
    assert v6["ips"] == ["2001:db8::1"]


def test_parse_windows_lines():
    assert traceroute.parse_header("Tracing route to google.com [142.250.80.46]")["ip"] == "142.250.80.46"
    parsed = [p for p in map(traceroute.parse_windows_line, WINDOWS_OUTPUT.splitlines()) if p]
    assert [p["hop"] for p in parsed] == [1, 2, 3, 4, 5]
    assert parsed[0]["rtts"] == [0.5, 0.5, 0.5] and parsed[0]["ips"] == ["192.168.1.1"]
    assert parsed[1]["rtts"] == [9.0, None, 10.0]
    assert parsed[2]["ips"] == [] and parsed[2]["rtts"] == [None, None, None]
    # Other languages: the words differ but the layout doesn't.
    assert traceroute.parse_windows_line("  3     *        *        *     Zeitüberschreitung der Anforderung.")["ips"] == []
    unreachable = traceroute.parse_windows_line("  6  192.168.1.1  reports: Destination host unreachable.")
    assert unreachable["ips"] == ["192.168.1.1"] and unreachable["notes"] == ["unreachable"]


def test_build_args_and_validation():
    assert traceroute.build_args("tracert", "google.com", 30, windows=True) == ["tracert", "-d", "-h", "30", "-w", "2000", "google.com"]
    assert traceroute.build_args("/usr/sbin/traceroute", "1.1.1.1", 99, windows=False)[-3:] == ["-m", "64", "1.1.1.1"]
    assert traceroute.validate_target(" https://example.com/path ") == "example.com"
    for bad in ("", "-n", "rm -rf /", "a;b"):
        with pytest.raises(traceroute.TraceError):
            traceroute.validate_target(bad)


def hop(n, ips, rtts):
    return traceroute.summarize_hop({"hop": n, "ips": ips, "rtts": rtts, "notes": []})


def test_scope():
    assert traceroute.scope("192.168.1.1") == "local"
    assert traceroute.scope("100.92.0.1") == "cgnat"
    assert traceroute.scope("8.8.8.8") == "public"


def test_findings_good_path_with_distance_jump():
    hops = [hop(1, ["192.168.1.1"], [1.2, 1.0, 1.1]), hop(2, ["100.92.0.1"], [9, 10, 9]), hop(3, [], [None] * 3),
            hop(4, ["68.86.90.1"], [12, 13, 12]), hop(5, ["142.250.80.46"], [95, 94, 96])]
    info = {"192.168.1.1": {"scope": "local"}, "100.92.0.1": {"scope": "cgnat"},
            "68.86.90.1": {"scope": "public", "asn": {"asn": "7922", "org": "Comcast", "country": "US"}},
            "142.250.80.46": {"scope": "public", "asn": {"asn": "15169", "org": "Google LLC", "country": "GB"}}}
    recs = {r["title"]: r for r in traceroute.findings("google.com", "142.250.80.46", hops, info)}
    assert "Reached google.com in 5 hops" in recs
    assert "Your router answers quickly (1.1 ms)" in recs
    jump = recs["Delay jumps by 82 ms at hop 5"]
    assert jump["severity"] == "info" and "different countries" in jump["detail"]  # distance, not a fault
    assert "1 hop didn't respond (3)" in recs
    path = traceroute.path_summary(hops, info)
    assert [p["name"] for p in path] == ["your network", "your ISP", "Comcast", "Google LLC"]


def test_findings_slow_wifi_and_real_loss():
    hops = [hop(1, ["192.168.1.1"], [35, 41, 38]), hop(2, ["8.8.4.4"], [45, None, 47]), hop(3, ["8.8.8.8"], [50, None, 49])]
    info = {"192.168.1.1": {"scope": "local"}}
    recs = {r["title"]: r for r in traceroute.findings("8.8.8.8", "8.8.8.8", hops, info)}
    assert recs["Slow first hop: your router takes 38 ms"]["severity"] == "warning"
    assert recs["Packet loss from hop 2 to the destination"]["severity"] == "warning"


def test_findings_not_reached_and_harmless_intermediate_loss():
    hops = [hop(1, ["192.168.1.1"], [1, 1, 1]), hop(2, ["8.8.4.4"], [10, None, 11]), hop(3, ["9.9.9.9"], [12, 12, 12]),
            hop(4, [], [None] * 3)]
    titles = [r["title"] for r in traceroute.findings("example.com", "93.184.215.14", hops, {"192.168.1.1": {"scope": "local"}})]
    assert "The trace didn't get a reply from example.com" in titles
    assert "Some intermediate hops dropped probes" in titles


def test_run_streams_hops(monkeypatch):
    async def fake_stream(args):
        yield "err", MAC_HEADER  # macOS prints the header on stderr
        for line in MAC_OUTPUT.splitlines():
            yield "out", line
        yield "exit", 0

    async def fake_enrich(ip):
        return {"ip": ip, "hostname": f"host-{ip}", "scope": traceroute.scope(ip), "asn": None}

    monkeypatch.setattr(traceroute, "IS_WINDOWS", False)
    monkeypatch.setattr(traceroute, "find_command", lambda: "/usr/sbin/traceroute")
    monkeypatch.setattr(traceroute, "stream_cmd", fake_stream)
    monkeypatch.setattr(traceroute, "enrich", fake_enrich)

    async def run():
        return [ev async for ev in traceroute.run("google.com", 30)]

    events = asyncio.run(run())
    assert events[0]["type"] == "start" and events[1] == {"type": "resolved", "name": "google.com", "ip": "142.250.80.46"}
    hop_events = [e["hop"] for e in events if e["type"] == "hop"]
    assert [h["hop"] for h in hop_events] == [1, 2, 3, 4, 4, 5]  # hop 4 is re-sent when its second address arrives
    assert hop_events[4]["ips"] == ["68.86.90.1", "68.86.90.5"] and hop_events[4]["rtts"] == [12.311, 13.402, 12.998]
    done = events[-1]
    assert done["type"] == "done" and [h["hop"] for h in done["hops"]] == [1, 2, 3, 4, 5]
    assert done["info"]["192.168.1.1"]["hostname"] == "host-192.168.1.1"
    assert any(f["title"].startswith("Reached google.com") for f in done["findings"])


def test_run_unknown_host(monkeypatch):
    async def fake_stream(args):
        yield "err", "traceroute: unknown host nosuchhost.invalid"
        yield "exit", 64

    monkeypatch.setattr(traceroute, "find_command", lambda: "/usr/sbin/traceroute")
    monkeypatch.setattr(traceroute, "stream_cmd", fake_stream)

    async def run():
        return [ev async for ev in traceroute.run("nosuchhost.invalid")]

    with pytest.raises(traceroute.TraceError, match="Couldn't find"):
        asyncio.run(run())


def test_api_routes(monkeypatch):
    client = TestClient(app)
    assert "installed" in client.get("/api/traceroute/status").json()
    body = client.get("/api/traceroute", params={"target": "-rf"}).text
    assert '"type": "error"' in body and "host name or IP address" in body
    assert client.get("/api/traceroute", params={"target": "x.com", "max_hops": 500}).status_code == 422
