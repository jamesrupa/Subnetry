import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from subnetry.server import app
from subnetry.tools import dnsinfo, macvendor, portref, subnetcalc

client = TestClient(app)

# --- Subnet calculator ----------------------------------------------------------------------


def test_subnet_basic_24():
    r = subnetcalc.calculate("192.168.1.10/24")
    assert r["network"] == "192.168.1.0"
    assert r["broadcast"] == "192.168.1.255"
    assert (r["first_usable"], r["last_usable"]) == ("192.168.1.1", "192.168.1.254")
    assert r["usable_hosts"] == 254 and r["total_addresses"] == 256
    assert r["netmask"] == "255.255.255.0" and r["wildcard"] == "0.0.0.255"
    assert r["class"] == "C" and r["type"].startswith("Private")
    assert r["binary"]["netmask"] == "11111111.11111111.11111111.00000000"


@pytest.mark.parametrize("text", ["10.20.30.40 255.255.252.0", "10.20.30.40/255.255.252.0", "10.20.30.40 0.0.3.255"])
def test_subnet_mask_forms(text):
    assert subnetcalc.calculate(text)["cidr"] == "10.20.28.0/22"


def test_subnet_point_to_point_and_host():
    r31 = subnetcalc.calculate("172.16.0.0/31")
    assert r31["usable_hosts"] == 2 and r31["broadcast"] is None
    r32 = subnetcalc.calculate("8.8.8.8")
    assert r32["prefix"] == 32 and r32["usable_hosts"] == 1 and r32["type"].startswith("Public")


def test_subnet_special_ranges():
    assert subnetcalc.calculate("100.64.1.1/10")["type"].startswith("Carrier-grade")
    assert subnetcalc.calculate("203.0.113.5/24")["type"].startswith("Documentation")
    assert subnetcalc.calculate("127.0.0.1/8")["type"].startswith("Loopback")
    assert subnetcalc.calculate("192.168.1.0/24")["is_network_address"]


def test_subnet_ipv6():
    r = subnetcalc.calculate("2001:db8:abcd::1/48")
    assert r["version"] == 6 and r["cidr"] == "2001:db8:abcd::/48"
    assert r["broadcast"] is None and r["class"] is None
    assert r["exploded"].startswith("2001:0db8:abcd:0000")


@pytest.mark.parametrize("bad", ["", "300.1.1.1/24", "10.0.0.1/33", "10.0.0.1 255.0.255.0", "a b c"])
def test_subnet_errors(bad):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.calculate(bad)


def test_subnet_split_and_summarize():
    s = subnetcalc.split("192.168.0.0/24", 26)
    assert s["count"] == 4 and [n["cidr"] for n in s["subnets"]][-1] == "192.168.0.192/26"
    big = subnetcalc.split("10.0.0.0/8", 30)
    assert big["count"] == 2 ** 22 and big["shown"] == subnetcalc.MAX_SUBNETS
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.split("192.168.0.0/24", 20)
    m = subnetcalc.summarize("192.168.0.0/24\n192.168.1.0/24, 192.168.2.0/24")
    assert m["collapsed"] == ["192.168.0.0/23", "192.168.2.0/24"]
    assert m["supernet"] == "192.168.0.0/22"


def test_subnet_api():
    r = client.get("/api/subnet", params={"q": "10.0.0.5/29", "split_prefix": 30})
    assert r.status_code == 200 and r.json()["split"]["count"] == 2
    assert client.get("/api/subnet", params={"q": "nope"}).status_code == 400
    assert client.get("/api/subnet/summarize", params={"q": "10.0.0.0/25 10.0.0.128/25"}).json()["collapsed"] == ["10.0.0.0/24"]

# --- MAC vendor lookup ------------------------------------------------------------------------

NMAP_SAMPLE = """# comment
3C22FB Apple
B827EB Raspberry Pi Foundation
70B3D5 IEEE Registration Authority
70B3D5ABC Tiny Sensor Co
"""


@pytest.fixture
def mac_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SUBNETRY_REPORTS_DIR", str(tmp_path))
    nmap_file = tmp_path / "nmap-mac-prefixes"
    nmap_file.write_text(NMAP_SAMPLE)
    monkeypatch.setattr(macvendor, "_nmap_file", lambda: nmap_file)
    macvendor.load(force=True)
    yield tmp_path
    monkeypatch.setattr(macvendor, "_db", None)


def test_mac_normalize():
    assert macvendor.normalize("3c:22:fb:12:34:56") == "3C22FB123456"
    assert macvendor.normalize("3c22.fb12.3456") == "3C22FB123456"
    assert macvendor.normalize("3C-22-FB") == "3C22FB"
    assert macvendor.normalize("xyz") is None


def test_mac_lookup(mac_db):
    r = macvendor.lookup("3c-22-fb-12-34-56")
    assert r["vendor"] == "Apple" and r["mac"] == "3C:22:FB:12:34:56" and not r["randomized"]
    assert macvendor.lookup("70:B3:D5:AB:C1:23")["vendor"] == "Tiny Sensor Co"  # MA-S beats MA-L
    assert macvendor.lookup("70:B3:D5:00:00:01")["vendor"] == "IEEE Registration Authority"
    assert macvendor.vendor_for("b8:27:eb:00:11:22") == "Raspberry Pi Foundation"
    rnd = macvendor.lookup("DA:A1:19:00:00:01")
    assert rnd["randomized"] and rnd["vendor"] is None and "private" in rnd["note"]
    mc = macvendor.lookup("01:00:5E:00:00:FB")
    assert mc["multicast"] and not mc["randomized"]
    bc = macvendor.lookup("FF:FF:FF:FF:FF:FF")
    assert bc["broadcast"] and not bc["randomized"]
    assert not macvendor.lookup("12")["valid"]
    assert macvendor.status() == {"entries": 4, "source": "Nmap's vendor list"}


def test_mac_ieee_update(mac_db):
    csv_body = {
        "oui.csv": "Registry,Assignment,Organization Name,Organization Address\nMA-L,3C22FB,Apple Inc.,Cupertino\n",
        "mam.csv": "Registry,Assignment,Organization Name,Organization Address\nMA-M,70B3D51,Medium Co,Somewhere\n",
    }

    def handler(request):
        name = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, text=csv_body[name]) if name in csv_body else httpx.Response(503)

    st = asyncio.run(macvendor.update_from_ieee(httpx.MockTransport(handler)))
    assert st["entries"] == 2 and st["source"].startswith("IEEE") and len(st["warnings"]) == 1
    assert json.loads((mac_db / ".oui-cache.json").read_text())["entries"]["3C22FB"] == "Apple Inc."
    assert macvendor.lookup("3C:22:FB:00:00:00")["vendor"] == "Apple Inc."


def test_mac_ieee_update_failure(mac_db):
    with pytest.raises(RuntimeError):
        asyncio.run(macvendor.update_from_ieee(httpx.MockTransport(lambda r: httpx.Response(500))))
    assert macvendor.status()["source"] == "Nmap's vendor list"


def test_mac_api(mac_db):
    assert client.get("/api/mac", params={"q": "B8:27:EB:01:02:03"}).json()["vendor"] == "Raspberry Pi Foundation"
    assert client.get("/api/mac/status").json()["entries"] == 4

# --- Port reference -----------------------------------------------------------------------------


def test_portref_data_is_consistent():
    seen = set()
    for p in portref.PORTS:
        assert p["risk"] in ("ok", "caution", "risky")
        assert p["category"] in portref.CATEGORIES
        assert 0 < p["port"] < 65536 and p["description"]
        key = (p["port"], p["protocol"])
        assert key not in seen, key
        seen.add(key)


def test_portref_search():
    assert {p["name"] for p in portref.search("443")} >= {"HTTPS"}
    assert all(p["port"] == 22 for p in portref.search("22"))
    assert any(p["port"] == 9100 for p in portref.search("printer"))
    assert all(p["category"] == "Remote access" for p in portref.search(category="Remote access"))
    assert portref.describe(3389) and not portref.describe(1)
    body = client.get("/api/portref").json()
    assert body["total"] == len(body["ports"]) and len(body["ranges"]) == 3

# --- DNS -------------------------------------------------------------------------------------------


def test_dns_clean_name():
    assert dnsinfo.clean_name("https://WWW.Example.com/path?q=1") == "www.example.com"
    assert dnsinfo.clean_name(" example.com. ") == "example.com"
    assert dnsinfo.clean_name("1.1.1.1") == "1.1.1.1"
    assert dnsinfo.clean_name("bücher.de") == "xn--bcher-kva.de"
    with pytest.raises(dnsinfo.DnsError):
        dnsinfo.clean_name("   ")


def test_dns_spf():
    spf = dnsinfo.parse_spf("v=spf1 ip4:203.0.113.0/24 include:_spf.google.com mx -all")
    assert spf["policy"] == "-" and spf["lookups"] == 2 and not spf["warnings"]
    assert "Google" in spf["terms"][1]["explanation"]
    assert any("+all" in w for w in dnsinfo.parse_spf("v=spf1 +all")["warnings"])
    assert any("no 'all'" in w for w in dnsinfo.parse_spf("v=spf1 mx")["warnings"])
    many = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " ~all"
    assert any("at most 10" in w for w in dnsinfo.parse_spf(many)["warnings"])


def test_dns_dmarc_and_soa():
    d = dnsinfo.parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50; adkim=s")
    assert d["policy"] == "reject"
    assert any("50%" in line for line in d["lines"]) and any("strict" in line for line in d["lines"])
    assert dnsinfo.parse_soa_email("host\\.master.example.com.") == "host.master@example.com"
    details = dnsinfo.explain_soa("ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 300")
    assert any("hostmaster@example.com" in line for line in details)


def test_dns_dkim_key():
    assert dnsinfo.dkim_key("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC")
    assert not dnsinfo.dkim_key("v=DKIM1; p=")


def _txt(*values):
    return {"status": "ok", "records": [{"value": v, **dnsinfo.explain_txt(v)} for v in values]}


def test_dns_findings():
    mx = {"status": "ok", "records": [{"value": "10 mail.example.com", "explanation": "Mail server"}]}
    results = {"MX": mx, "TXT": _txt("v=spf1 +all"), "A": {"status": "ok", "records": []}, "CAA": {"status": "none"},
               "NS": {"status": "ok", "records": [{"value": "ns1.example.com"}]}}
    titles = {f["title"]: f["severity"] for f in dnsinfo.findings("example.com", results, None, [])}
    assert titles["SPF record problem"] == "critical"
    assert "No DMARC policy" in titles and "No CAA record" in titles and "Only one name server" in titles
    # A timed-out TXT query must never turn into "No SPF record".
    results["TXT"] = {"status": "timeout"}
    titles = {f["title"] for f in dnsinfo.findings("example.com", results, None, [], dmarc_status="timeout")}
    assert "No SPF record" not in titles and "No DMARC policy" not in titles
    assert "Couldn't load TXT records" in titles


def test_dns_api_validation():
    assert client.get("/api/dns", params={"q": "  "}).status_code == 400
    assert client.get("/api/dns", params={"q": "example.com", "resolver": "evil"}).status_code == 422
    body = client.get("/api/dns/explainers").json()
    assert {"SPF", "DMARC", "TTL"} <= {x["type"] for x in body["explainers"]}
    assert "cloudflare" in body["resolvers"]

# --- Network scanner: picking the right LAN, explaining empty scans ---------------------------

import ipaddress  # noqa: E402

from subnetry.tools import netinfo, netscan  # noqa: E402


def test_rank_networks_prefers_internet_lan():
    nets = [
        {"interface": "bridge100", "address": "192.168.64.1", "network": "192.168.64.0/24"},
        {"interface": "Ethernet 2", "address": "192.168.56.1", "network": "192.168.56.0/24"},
        {"interface": "utun4", "address": "10.8.0.2", "network": "10.8.0.0/24"},
        {"interface": "en0", "address": "192.168.1.20", "network": "192.168.1.0/24"},
        {"interface": "vEthernet (WSL)", "address": "172.20.0.1", "network": "172.20.0.0/20"},
    ]
    assert netinfo.rank_networks(nets, "192.168.1.20")[0]["interface"] == "en0"
    # Without a route to the internet, physical adapters still beat VPN/VM ones.
    order = [n["interface"] for n in netinfo.rank_networks(nets, None)]
    assert order.index("en0") < order.index("bridge100") and order.index("en0") < order.index("utun4")
    assert order.index("vEthernet (WSL)") > order.index("en0")


def test_lonely_scan_notice():
    net = ipaddress.IPv4Network("192.168.56.0/24")
    own = {"192.168.56.1", "192.168.1.20"}
    assert netscan.lonely_scan_notice(net, 3, own, "192.168.1.1", False) is None
    assert "Local Network" in netscan.lonely_scan_notice(net, 0, own, "192.168.1.1", True)
    assert "VPN or virtual-machine" in netscan.lonely_scan_notice(net, 0, own, "192.168.1.1", False)
    home = ipaddress.IPv4Network("192.168.1.0/24")
    assert "client isolation" in netscan.lonely_scan_notice(home, 0, own, "192.168.1.1", False)


def test_old_mac_launcher_gets_local_network_key(tmp_path, monkeypatch):
    import plistlib

    from subnetry import desktop_app

    monkeypatch.setattr(desktop_app.sys, "platform", "darwin")
    app = desktop_app.build_macos_app(tmp_path, python="/opt/py/bin/python3")
    plist = app / "Contents" / "Info.plist"
    info = plistlib.loads(plist.read_bytes())
    assert "NSLocalNetworkUsageDescription" in info
    assert not desktop_app.refresh_macos_launcher(tmp_path)  # already current
    # Simulate a launcher from an older version: no Local Network key, no SUBNETRY_LAUNCHER.
    del info["NSLocalNetworkUsageDescription"]
    plist.write_bytes(plistlib.dumps(info))
    script = app / "Contents" / "MacOS" / "Subnetry"
    script.write_text(script.read_text().replace(desktop_app.LAUNCHER_REVISION, "")
                      .replace('"/opt/py/bin/python3" -m', 'exec "/opt/py/bin/python3" -m'))
    assert desktop_app.refresh_macos_launcher(tmp_path)
    assert "NSLocalNetworkUsageDescription" in plistlib.loads(plist.read_bytes())
    text = script.read_text()
    assert '\n"/opt/py/bin/python3" -m subnetry' in text and "exec " not in text


def test_mac_local_network_help_names_the_right_app(monkeypatch):
    monkeypatch.setenv("SUBNETRY_LAUNCHER", "app")
    assert "turn Subnetry on" in netscan.mac_local_network_help()
    monkeypatch.delenv("SUBNETRY_LAUNCHER")
    monkeypatch.setenv("TERM_PROGRAM", "Apple_Terminal")
    assert "turn Terminal on" in netscan.mac_local_network_help()
