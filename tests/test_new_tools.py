import asyncio
import sys
from pathlib import Path

import httpx
import pytest

from subnetry.tools import ipinfo, nmapscan, traffic, wifimonitor
from subnetry.tools.netscan import ScanError

# --- Wi-Fi monitor parsers ------------------------------------------------------------

NETSH_INTERFACES = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    Physical address       : 3c:9c:0f:aa:bb:cc
    Interface type         : Primary
    State                  : connected
    SSID                   : HomeNet
    AP BSSID               : 11:22:33:44:55:66
    Band                   : 5 GHz
    Channel                : 44
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 720.5
    Signal                 : 92%
    Rssi                   : -48
    Profile                : HomeNet
"""

IW_LINK = """Connected to aa:bb:cc:dd:ee:ff (on wlp2s0)
	SSID: HomeNet
	freq: 5180.0
	RX: 1234 bytes (10 packets)
	signal: -61 dBm
	rx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
	tx bitrate: 650.0 MBit/s
"""

PROC_NET_WIRELESS = """Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlp2s0: 0000   54.  -56.  -256        0      0      0      0     29        0
"""


def test_parse_netsh_interfaces():
    c = wifimonitor.parse_netsh_interfaces(NETSH_INTERFACES)
    assert c["ssid"] == "HomeNet" and c["bssid"] == "11:22:33:44:55:66"  # not the adapter's own MAC
    assert c["signal_dbm"] == -48 and c["signal_percent"] == 92
    assert c["band"] == "5 GHz" and c["channel"] == 44 and c["rx_rate_mbps"] == 866.7
    assert wifimonitor.parse_netsh_interfaces(NETSH_INTERFACES.replace("connected", "disconnected")) is None


def test_parse_iw_link_and_proc():
    c = wifimonitor.parse_iw_link(IW_LINK, "wlp2s0")
    assert c["bssid"] == "AA:BB:CC:DD:EE:FF" and c["signal_dbm"] == -61
    assert c["channel"] == 36 and c["band"] == "5 GHz" and c["tx_rate_mbps"] == 650.0
    assert wifimonitor.parse_iw_link("Not connected.") is None
    assert wifimonitor.parse_proc_net_wireless(PROC_NET_WIRELESS) == {"wlp2s0": -56}


@pytest.mark.parametrize("freq,ch", [(2412, 1), (2437, 6), (2484, 14), (5180, 36), (5745, 149), (5975, 5), (None, None)])
def test_freq_to_channel(freq, ch):
    assert wifimonitor.freq_to_channel(freq) == ch


def sample(bssid, dbm, ssid="HomeNet", band="5 GHz"):
    return {"ssid": ssid, "bssid": bssid, "signal_dbm": dbm, "band": band}


def test_roam_tracker_events():
    tr = wifimonitor.RoamTracker()
    assert tr.feed(sample("AA", -70), 0) == []
    roam = tr.feed(sample("BB", -50), 2)
    assert roam[0]["kind"] == "roam" and roam[0]["good"] and "+20 dB" in roam[0]["message"]
    assert tr.feed(None, 4)[0]["kind"] == "disconnect"
    assert tr.feed(sample("BB", -52), 6)[0]["kind"] == "reconnect"
    assert tr.feed(sample("CC", -52, ssid="Other"), 8)[0]["kind"] == "network_change"


def test_sticky_detection():
    tr = wifimonitor.RoamTracker()
    cur = sample("AA", -74)
    nets = [dict(sample("AA", -74), channel=36), dict(sample("BB", -55), channel=149), dict(sample("ZZ", -40, ssid="Neighbor"))]
    ev = tr.check_neighbors(nets, cur, 10)
    assert ev and ev[0]["kind"] == "sticky" and ev[0]["better_bssid"] == "BB"
    assert tr.check_neighbors(nets, cur, 30) == []  # rate-limited
    assert tr.check_neighbors(nets, sample("AA", -60), 200) == []  # own signal still fine
    aps = wifimonitor.same_network_aps(nets, cur)
    assert [a["bssid"] for a in aps] == ["BB", "AA"] and aps[1]["is_current"]


def test_monitor_streams_samples_and_scans(monkeypatch):
    seq = iter([sample("AA", -60), sample("AA", -62), sample("BB", -50)] + [sample("BB", -50)] * 50)

    async def fake_conn():
        return next(seq)

    async def fake_scan():
        return {"networks": [dict(sample("AA", -60), channel=36), dict(sample("BB", -50), channel=149)]}

    monkeypatch.setattr(wifimonitor, "current_connection", fake_conn)
    monkeypatch.setattr(wifimonitor.wifiscan, "scan_wifi", fake_scan)

    async def run():
        out = []
        async for ev in wifimonitor.monitor(interval=0.1, scan_every=0.1, max_seconds=3.5):
            out.append(ev)
        return out
    events = asyncio.run(run())
    kinds = [e["type"] for e in events]
    assert kinds.count("sample") >= 10 and "aps" in kinds
    assert any(e.get("kind") == "roam" for e in events)


# --- Public IP ------------------------------------------------------------------------

IPINFO = {"ip": "203.0.113.7", "hostname": "host.isp.example", "city": "Austin", "region": "Texas", "country": "US",
          "loc": "30.2672,-97.7431", "org": "AS7922 Comcast Cable Communications, LLC", "postal": "78701",
          "timezone": "America/Chicago"}


def test_ipinfo_lookup_self_and_ipv6():
    def handler(req: httpx.Request):
        if req.url.host == "ipinfo.io":
            return httpx.Response(200, json=IPINFO)
        if req.url.host == "api64.ipify.org":
            return httpx.Response(200, json={"ip": "2001:db8::1"})
        return httpx.Response(500)
    info = asyncio.run(ipinfo.lookup(transport=httpx.MockTransport(handler)))
    assert info["isp"] == "Comcast Cable Communications, LLC" and info["asn"] == "AS7922"
    assert info["latitude"] == 30.2672 and info["ipv6"] == "2001:db8::1" and info["is_self"]


def test_ipinfo_falls_back_to_ipwhois():
    def handler(req: httpx.Request):
        if req.url.host == "ipinfo.io":
            return httpx.Response(429)
        return httpx.Response(200, json={"success": True, "ip": "8.8.8.8", "city": "Mountain View", "country_code": "US",
                                         "connection": {"asn": 15169, "isp": "Google LLC"}, "timezone": {"id": "America/Los_Angeles"}})
    info = asyncio.run(ipinfo.lookup("8.8.8.8", transport=httpx.MockTransport(handler)))
    assert info["source"] == "ipwho.is" and info["asn"] == "AS15169" and not info["is_self"]


@pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.1", "127.0.0.1", "not-an-ip"])
def test_ipinfo_rejects_non_public(ip):
    with pytest.raises(ipinfo.IpInfoError):
        ipinfo.validate_public_ip(ip)


# --- Nmap -----------------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -T4 -F -O 192.168.1.0/24" version="7.94">
<host><status state="up"/>
<address addr="192.168.1.1" addrtype="ipv4"/><address addr="A4:2B:B0:11:22:33" addrtype="mac" vendor="TP-Link"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="BusyBox telnetd"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd" version="1.4"/>
  <script id="http-title" output="Router Login"/></port>
<port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
</ports>
<os><osmatch name="Linux 4.15 - 5.8" accuracy="96"/></os>
</host>
<host><status state="down"/><address addr="192.168.1.2" addrtype="ipv4"/></host>
<runstats><finished elapsed="12.5" summary="Nmap done: 256 IP addresses (1 host up) scanned in 12.5 seconds"/><hosts up="1" down="255" total="256"/></runstats>
</nmaprun>"""


def test_parse_nmap_xml_and_findings():
    r = nmapscan.parse_xml(NMAP_XML)
    assert r["hosts_up"] == 1 and len(r["hosts"]) == 1
    h = r["hosts"][0]
    assert h["vendor"] == "TP-Link" and h["hostnames"] == ["router.lan"] and h["os"][0]["accuracy"] == 96
    assert [p["port"] for p in h["ports"]] == [23, 80]  # closed ports dropped
    assert h["ports"][1]["product"] == "lighttpd 1.4" and h["ports"][1]["scripts"][0]["output"] == "Router Login"
    titles = [f["title"] for f in nmapscan.findings(r, gateway="192.168.1.1")]
    assert any("Telnet" in t for t in titles) and "Router admin page uses plain HTTP" in titles


def test_parse_real_nmap_output():
    r = nmapscan.parse_xml((Path(__file__).parent / "nmap_sample.xml").read_text())
    assert r["hosts"][0]["ip"] == "127.0.0.1" and r["version"]


def test_nmap_progress_lines():
    assert nmapscan.parse_line("SYN Stealth Scan Timing: About 45.20% done; ETC: 16:57 (0:00:12 remaining)") == \
        {"type": "progress", "task": "SYN Stealth Scan", "percent": 45.2}
    assert nmapscan.parse_line("Discovered open port 22/tcp on 192.168.1.5") == \
        {"type": "open_port", "ip": "192.168.1.5", "port": 22, "protocol": "tcp"}
    assert nmapscan.parse_line("Read data files from: /usr/bin/../share/nmap") is None


@pytest.mark.parametrize("target", ["8.8.8.8", "10.0.0.0/8", "-oN /tmp/x", "192.168.1.1 --script evil", ""])
def test_nmap_rejects_bad_targets(target):
    with pytest.raises(ScanError):
        nmapscan.validate_target(target)


def test_nmap_args():
    assert nmapscan.validate_target("192.168.1.7") == "192.168.1.7"
    assert nmapscan.validate_target("192.168.1.7/24") == "192.168.1.0/24"
    args = nmapscan.build_args("nmap", "192.168.1.0/24", "standard", True, True, "/tmp/o.xml")
    assert args[-1] == "192.168.1.0/24" and "-O" in args and "-sC" in args and "-sV" in args
    assert "-O" not in nmapscan.build_args("nmap", "192.168.1.1", "ping", True, False, "/tmp/o.xml")
    with pytest.raises(ScanError):
        nmapscan.build_args("nmap", "192.168.1.1", "bogus", False, False, "/tmp/o.xml")


@pytest.mark.skipif(not nmapscan.find_nmap(), reason="nmap not installed")
def test_nmap_live_scan_of_localhost():
    async def run():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            # A custom port list isn't a profile, so scan the top ports and check nmap ran end to end.
            return port, [ev async for ev in nmapscan.run_scan("127.0.0.1", "quick")]
    _, events = asyncio.run(run())
    assert events[0]["type"] == "start" and events[-1]["type"] == "result"
    assert events[-1]["result"]["hosts"][0]["ip"] == "127.0.0.1"


# --- Traffic --------------------------------------------------------------------------

def line(**kw):
    return "\t".join(kw.get(f.replace(".", "_"), "") for f in traffic.FIELDS)


def pkt(t, size, protos, src, dst, sport="", dport="", udp=False, **kw):
    ports = {"udp_srcport": sport, "udp_dstport": dport} if udp else {"tcp_srcport": sport, "tcp_dstport": dport}
    return traffic.parse_fields(line(frame_time_epoch=str(t), frame_len=str(size), frame_protocols=protos,
                                     ip_src=src, ip_dst=dst, **ports, **kw))


def test_traffic_analyzer_end_to_end():
    a = traffic.TrafficAnalyzer()
    me, dns = "192.168.1.12", "192.168.1.1"
    a.add(pkt(1.0, 70, "eth:ethertype:ip:udp:dns", me, dns, "5000", "53", udp=True, dns_qry_name="youtube.com", dns_flags_response="False"))
    a.add(pkt(1.1, 120, "eth:ethertype:ip:udp:dns", dns, me, "53", "5000", udp=True, dns_qry_name="youtube.com",
              dns_flags_response="True", dns_flags_rcode="0", dns_a="142.250.1.1,142.250.1.2"))
    a.add(pkt(1.2, 600, "eth:ethertype:ip:tcp:tls", me, "142.250.1.1", "40000", "443",
              tls_handshake_extensions_server_name="www.youtube.com"))
    for i in range(10):  # ACK-only packets on the same connection inherit "tls"
        a.add(pkt(1.3 + i / 10, 1500, "eth:ethertype:ip:tcp", "142.250.1.1", me, "443", "40000"))
    a.add(pkt(2.0, 400, "eth:ethertype:ip:tcp:http", me, "93.184.216.34", "40001", "80",
              http_host="example.com", http_request_method="GET"))
    a.add(pkt(2.1, 90, "eth:ethertype:ip:udp:dns", dns, me, "53", "5001", udp=True, dns_qry_name="typo.exmaple",
              dns_flags_response="True", dns_flags_rcode="3"))
    snap = a.snapshot()
    protos = {p["key"]: p for p in snap["protocols"]}
    assert protos["tls"]["packets"] == 11 and "other-tcp" not in protos
    dest = snap["destinations"][0]
    assert dest["name"] == "www.youtube.com" and dest["bytes"] == 600 + 15000 and dest["protocol"] == "HTTPS / TLS"
    assert snap["devices"][0]["ip"] == me
    feed = [f["text"] for f in snap["feed"]]
    assert f"{me} looked up youtube.com" in feed and any("unencrypted HTTP with example.com" in t for t in feed)
    titles = [i["title"] for i in snap["insights"]]
    assert "Unencrypted HTTP traffic" in titles and "1 failed DNS lookup" in titles and "DNS servers in use" in titles
    rin, rout = a.take_rates()
    assert rin == 15000 and rout == 600 + 400  # LAN-only DNS with the router is not internet traffic and a.take_rates() == (0, 0)


@pytest.mark.parametrize("protos,sport,dport,udp,expected", [
    ("eth:ethertype:ip:udp:quic", 50000, 443, True, "quic"),
    ("eth:ethertype:ip:udp", 50000, 443, True, "quic"),
    ("eth:ethertype:ip:udp:mdns", 5353, 5353, True, "mdns"),
    ("eth:ethertype:arp", None, None, False, "arp"),
    ("eth:ethertype:ip:tcp", 50000, 22, False, "ssh"),
    ("eth:ethertype:ip:tcp", 50000, 9999, False, "other-tcp"),
])
def test_traffic_classify(protos, sport, dport, udp, expected):
    assert traffic.classify(protos, sport, dport, udp) == expected


def test_tshark_interface_parsing():
    text = ("1. eth0\n2. any\n3. lo (Loopback)\n"
            "4. \\Device\\NPF_{3B2C-11} (Wi-Fi)\n5. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n")
    ifaces = traffic.parse_interfaces(text)
    assert ifaces[0] == {"index": 1, "name": "eth0", "description": "eth0"}
    assert ifaces[3]["name"] == "\\Device\\NPF_{3B2C-11}" and ifaces[3]["description"] == "Wi-Fi"


def test_capture_rejects_option_injection():
    async def run():
        return [ev async for ev in traffic.capture("-w/etc/passwd", 5)]

    if traffic.find_tshark():
        with pytest.raises(RuntimeError):
            asyncio.run(run())


@pytest.mark.skipif(not traffic.find_tshark(), reason="tshark not installed")
def test_capture_reports_tshark_errors():
    async def run():
        return [ev async for ev in traffic.capture("no-such-interface0", 5)]
    events = asyncio.run(run())
    assert events[-1]["type"] == "error" and events[-1]["message"]


@pytest.mark.skipif(not traffic.find_tshark(), reason="tshark not installed")
def test_live_capture_on_loopback(tmp_path, monkeypatch):
    monkeypatch.setenv("SUBNETRY_REPORTS_DIR", str(tmp_path))

    async def run():
        async def chatter():
            await asyncio.sleep(1.5)
            for _ in range(5):
                try:
                    _, w = await asyncio.open_connection("127.0.0.1", 9)
                    w.close()
                except OSError:
                    pass
        task = asyncio.create_task(chatter())
        loopback = "lo0" if sys.platform == "darwin" else "lo"
        events = [ev async for ev in traffic.capture(loopback, 5, "tcp port 9", save=True)]
        await task
        return events
    events = asyncio.run(run())
    if events[-1]["type"] == "error":
        pytest.skip(f"capture not permitted here: {events[-1]['message']}")
    done = events[-1]
    assert done["type"] == "done" and done["packets"] >= 5
    assert (tmp_path / "captures" / done["pcap"]).stat().st_size > 0


# --- Nmap: public targets & hostnames ------------------------------------------------------

def test_public_targets_need_permission_and_size_limit():
    with pytest.raises(ScanError, match="public address"):
        nmapscan.check_target("8.8.8.8")
    t = nmapscan.check_target("8.8.8.8", authorized=True)
    assert t.public and t.single and t.value == "8.8.8.8"
    assert nmapscan.check_target("203.0.113.0/24", authorized=True).value == "203.0.113.0/24"
    with pytest.raises(ScanError, match="/24 or smaller"):
        nmapscan.check_target("8.8.0.0/16", authorized=True)
    lan = nmapscan.check_target("192.168.1.0/24")
    assert not lan.public and lan.value == "192.168.1.0/24"


def test_hostname_targets(monkeypatch):
    import socket as _socket

    def fake_getaddrinfo(host, *_a, **_k):
        ips = {"example.com": "93.184.216.34", "printer.lan": "192.168.1.50"}
        if host not in ips:
            raise _socket.gaierror(8, "nodename nor servname provided")
        return [(_socket.AF_INET, 1, 6, "", (ips[host], 0))]
    monkeypatch.setattr(nmapscan.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScanError, match=r"example\.com \(93\.184\.216\.34\)"):
        nmapscan.check_target("example.com")
    t = nmapscan.check_target("example.com", authorized=True)
    assert t.public and t.resolved == "93.184.216.34" and t.value == "example.com"
    assert not nmapscan.check_target("printer.lan").public
    with pytest.raises(ScanError, match="Couldn't resolve"):
        nmapscan.check_target("nope.invalid")
    for bad in ["-sV", "a..b", "host name", "x" * 300]:
        with pytest.raises(ScanError):
            nmapscan.check_target(bad, authorized=True)


def test_public_single_host_skips_ping():
    args = nmapscan.build_args("nmap", "8.8.8.8", "quick", False, False, "/tmp/o.xml", skip_ping=True)
    assert "-Pn" in args and args[-1] == "8.8.8.8"
    assert "-Pn" not in nmapscan.build_args("nmap", "8.8.8.8", "ping", False, False, "/tmp/o.xml", skip_ping=True)


def test_safe_concurrency_respects_low_file_limits(monkeypatch):
    from subnetry import system
    monkeypatch.setattr(system, "raise_open_file_limit", lambda target=4096: 256)  # macOS default
    assert system.safe_concurrency(11, 64) == 16  # (256 - 64) // 12
    monkeypatch.setattr(system, "raise_open_file_limit", lambda target=4096: 4096)
    assert system.safe_concurrency(11, 64) == 64


@pytest.mark.parametrize("stderr,expected,not_expected", [
    (["tshark: Invalid capture filter \"ip.addr == 1.2.3.4\" for interface 'Wi-Fi'.",
      "That string looks like a valid display filter; however, it isn't a valid capture filter (can't parse filter expression: syntax error).",
      "Note that display filters and capture filters don't have the same syntax"],
     "display-filter syntax", "wireshark group"),
    (["tshark: You don't have permission to capture on that device"], "wireshark", "capture filter"),
])
def test_capture_errors_are_explained(monkeypatch, stderr, expected, not_expected):
    async def fake_stream(args):
        for line in stderr:
            yield "err", line
        yield "exit", 1

    monkeypatch.setattr(traffic, "find_tshark", lambda: "/usr/bin/tshark")
    monkeypatch.setattr(traffic, "stream_cmd", fake_stream)
    monkeypatch.setattr(traffic.platform, "system", lambda: "Linux")

    async def run():
        return [ev async for ev in traffic.capture("eth0", 5, "ip.addr == 1.2.3.4" if "display" in expected else "")]

    err = next(e for e in asyncio.run(run()) if e["type"] == "error")["message"]
    assert expected.lower() in err.lower() and not_expected.lower() not in err.lower()
