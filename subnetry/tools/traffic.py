"""Traffic analyzer built on tshark, the command-line engine of Wireshark.

tshark captures and dissects packets; we ask it for a handful of fields per
packet (addresses, protocol stack, DNS names, TLS server names, HTTP hosts) and
turn them into a plain-English picture: what protocols are in use, which devices
are busiest, which sites/services they talk to, and anything worth a warning.

The capture can also be saved as a .pcapng file to open in Wireshark itself.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import time
from collections import Counter, defaultdict, deque
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

from ..system import IS_MAC, IS_WINDOWS, find_tool, run_cmd, stream_cmd
from . import report as report_mod

FIELDS = [
    "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.a", "dns.aaaa", "dns.flags.response", "dns.flags.rcode",
    "tls.handshake.extensions_server_name", "http.host", "http.request.method",
    "arp.src.proto_ipv4",
]

MAX_DURATION = 600
BENIGN_STDERR = re.compile(r"^(Capturing on|Running as user|\d+ packets? (captured|dropped)|Packets? (captured|dropped))", re.I)

INSTALL_HELP = {
    "Windows": "Install Wireshark from https://www.wireshark.org/download.html and keep the "
               "\"Npcap\" and \"TShark\" options ticked, then restart Subnetry.",
    "Darwin": "Install Wireshark from https://www.wireshark.org/download.html (or `brew install --cask wireshark`) "
              "and run the included \"Install ChmodBPF\" package so captures work without sudo.",
    "Linux": "Install with `sudo apt install tshark` (answer Yes to letting non-root users capture), then "
             "`sudo usermod -aG wireshark $USER` and log out/in.",
}
PERMISSION_HELP = {
    "Windows": "Npcap may be missing or restricted to administrators. Reinstall Wireshark with Npcap, or run Subnetry as administrator.",
    "Darwin": "Run the \"Install ChmodBPF\" package that ships with Wireshark, then restart Subnetry.",
    "Linux": "Add yourself to the wireshark group (`sudo usermod -aG wireshark $USER`, then log out/in), or run Subnetry with sudo.",
}

# Friendly names for what tshark reports in frame.protocols (highest layer wins).
PROTOCOLS = {
    "quic": ("QUIC (HTTP/3)", "Modern encrypted web and app traffic over UDP: YouTube, Google, Cloudflare sites."),
    "tls": ("HTTPS / TLS", "Encrypted web and app traffic. Contents are private; only the site name is visible."),
    "http": ("HTTP (unencrypted)", "Plain web traffic. Anyone on the path can read it."),
    "dns": ("DNS", "Name lookups: turning website names into IP addresses."),
    "mdns": ("mDNS / Bonjour", "Devices announcing themselves on the LAN: printers, AirPlay, Chromecast."),
    "llmnr": ("LLMNR", "Windows local name lookups."),
    "nbns": ("NetBIOS", "Legacy Windows name lookups and announcements."),
    "ssdp": ("SSDP / UPnP", "Smart TVs, consoles and media devices discovering each other."),
    "dhcp": ("DHCP", "Devices getting an IP address from the router."),
    "dhcpv6": ("DHCPv6", "IPv6 address assignment."),
    "arp": ("ARP", "Devices asking 'who has this IP?' on the local network."),
    "icmp": ("ICMP (ping)", "Pings and network error messages."),
    "icmpv6": ("ICMPv6", "IPv6 neighbour discovery and pings."),
    "ntp": ("NTP", "Clock synchronization."),
    "ssh": ("SSH", "Encrypted remote terminal sessions."),
    "telnet": ("Telnet", "Unencrypted remote terminal. Passwords are visible."),
    "ftp": ("FTP", "Unencrypted file transfer. Passwords are visible."),
    "smb2": ("SMB", "Windows file and printer sharing."),
    "smb": ("SMB v1", "Old, insecure Windows file sharing."),
    "rdp": ("RDP", "Windows Remote Desktop."),
    "stun": ("STUN", "Video/voice calls finding a path through the router."),
    "rtp": ("RTP", "Live voice/video call audio and video."),
    "igmp": ("IGMP", "Devices joining multicast groups (IPTV, streaming)."),
    "eapol": ("EAPOL", "Wi-Fi WPA handshake / authentication."),
    "pop": ("POP3", "Email download (unencrypted)."),
    "imap": ("IMAP", "Email access (unencrypted)."),
    "smtp": ("SMTP", "Sending email."),
    "snmp": ("SNMP", "Network device monitoring."),
}
PROTOCOL_PRIORITY = list(PROTOCOLS)  # first match in this order wins
CLEARTEXT = {"http": "HTTP", "telnet": "Telnet", "ftp": "FTP", "pop": "POP3", "imap": "IMAP"}


def find_tshark() -> str | None:
    if IS_WINDOWS:
        extra = [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"]
    elif IS_MAC:
        extra = ["/Applications/Wireshark.app/Contents/MacOS/tshark", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"]
    else:
        extra = []
    return find_tool("tshark", extra)


def captures_dir() -> Path:
    return report_mod.reports_dir() / "captures"


def parse_interfaces(text: str) -> list[dict]:
    """`tshark -D` lines look like '1. eth0' or '5. \\Device\\NPF_{GUID} (Wi-Fi)'."""
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.+)\))?", line)
        if m:
            out.append({"index": int(m.group(1)), "name": m.group(2), "description": m.group(3) or m.group(2)})
    return out


async def status() -> dict:
    path = find_tshark()
    osname = platform.system()
    info = {"installed": bool(path), "path": path, "interfaces": [], "install_help": INSTALL_HELP.get(osname, INSTALL_HELP["Linux"])}
    if path:
        res = await run_cmd([path, "-D"], timeout=15)
        if res:
            info["interfaces"] = parse_interfaces(res.stdout)
            if not info["interfaces"] and res.stderr.strip():
                info["error"] = res.stderr.strip().splitlines()[-1] + " " + PERMISSION_HELP.get(osname, "")
    return info


# --- analysis -----------------------------------------------------------------------

def is_local(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_multicast or a.is_unspecified


# Well-known ports for packets that carry no payload of their own (e.g. TCP ACKs in an HTTPS session).
TCP_PORT_HINTS = {443: "tls", 853: "tls", 993: "tls", 995: "tls", 465: "tls", 22: "ssh", 3389: "rdp", 445: "smb2"}


def classify(protocols: str, sport: int | None, dport: int | None, udp: bool) -> str:
    layers = protocols.split(":")
    for key in PROTOCOL_PRIORITY:
        if key in layers:
            return key
    ports = {sport, dport}
    if udp and 443 in ports:
        return "quic"
    if not udp and "tcp" in layers:
        for port in (dport, sport):
            if port in TCP_PORT_HINTS:
                return TCP_PORT_HINTS[port]
    if "tcp" in layers:
        return "other-tcp"
    if "udp" in layers:
        return "other-udp"
    return layers[-1] if layers else "other"


def protocol_label(key: str) -> tuple[str, str]:
    if key in PROTOCOLS:
        return PROTOCOLS[key]
    if key == "other-tcp":
        return "Other TCP", "Connections tshark didn't identify (apps, games, VPNs)."
    if key == "other-udp":
        return "Other UDP", "Datagrams tshark didn't identify (games, VPNs, streaming)."
    return key.upper(), ""


def _int(v: str) -> int | None:
    v = v.split(",")[0]
    return int(v) if v.isdigit() else None


class TrafficAnalyzer:
    """Aggregates packets into per-second rates, protocol mix, devices, destinations and insights."""

    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.protocols: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # key -> [packets, bytes]
        self.devices: dict[str, dict] = defaultdict(lambda: {"sent": 0, "received": 0, "packets": 0, "protocols": Counter()})
        self.destinations: dict[str, dict] = {}
        self.ip_names: dict[str, str] = {}
        self.dns_servers: Counter = Counter()
        self.dns_failures: Counter = Counter()
        self.cleartext: dict[str, set] = defaultdict(set)
        self.feed: deque = deque(maxlen=80)
        self._seen_feed: set = set()
        self.second_in = self.second_out = 0  # bytes in the current interval (local <- remote / local -> remote)
        self.flows: dict[tuple, str] = {}  # connection -> protocol identified on it

    def _remote_key(self, ip: str) -> str:
        return self.ip_names.get(ip, ip)

    def _note(self, key: tuple, text: str, kind: str, ts: float) -> None:
        if key in self._seen_feed:
            return
        self._seen_feed.add(key)
        self.feed.appendleft({"t": round(ts - (self.first_ts or ts), 1), "kind": kind, "text": text})

    def add(self, f: dict) -> None:
        ts = float(f["frame.time_epoch"] or time.time())
        size = int(f["frame.len"] or 0)
        if self.first_ts is None:
            self.first_ts = ts
        self.packets += 1
        self.bytes += size
        src = f["ip.src"] or f["ipv6.src"] or f["arp.src.proto_ipv4"]
        dst = f["ip.dst"] or f["ipv6.dst"]
        udp = bool(f["udp.srcport"])
        sport = _int(f["tcp.srcport"] or f["udp.srcport"])
        dport = _int(f["tcp.dstport"] or f["udp.dstport"])
        proto = classify(f["frame.protocols"], sport, dport, udp)
        # Packets without payload (ACKs, handshakes) inherit the protocol seen on the same connection.
        flow = tuple(sorted([(src, sport), (dst, dport)], key=str)) if src and dst and sport else None
        if flow:
            if proto in ("other-tcp", "other-udp"):
                proto = self.flows.get(flow, proto)
            else:
                self.flows.setdefault(flow, proto)
        self.protocols[proto][0] += 1
        self.protocols[proto][1] += size

        # Learn names: DNS answers map IPs to the name that was looked up; TLS SNI / HTTP Host name the server.
        qname = f["dns.qry.name"].split(",")[0]
        if f["dns.flags.response"] in ("True", "1") and qname:
            for ip in (f["dns.a"] + "," + f["dns.aaaa"]).split(","):
                if ip:
                    self.ip_names[ip] = qname
            if f["dns.flags.rcode"] not in ("", "0"):
                self.dns_failures[qname] += 1
        server_name = f["tls.handshake.extensions_server_name"] or f["http.host"]
        if server_name and dst and not is_local(dst):
            self.ip_names[dst] = server_name.split(",")[0]

        # Direction: a local device talking to a remote one.
        local_src, local_dst = is_local(src), is_local(dst)
        if src and local_src:
            d = self.devices[src]
            d["sent"] += size
            d["packets"] += 1
            d["protocols"][proto] += 1
        if dst and local_dst and not (dst.startswith(("224.", "239.", "ff")) or dst.endswith(".255")):
            self.devices[dst]["received"] += size
        if local_src and dst and not local_dst:
            self.second_out += size
            self._dest(dst, size, proto, src)
        elif local_dst and src and not local_src:
            self.second_in += size
            self._dest(src, size, proto, dst)

        # Activity feed & insights
        if proto == "dns" and qname and f["dns.flags.response"] in ("False", "0") and src:
            self.dns_servers[dst] += 1
            self._note(("dns", src, qname), f"{src} looked up {qname}", "dns", ts)
        if f["tls.handshake.extensions_server_name"] and src:
            name = f["tls.handshake.extensions_server_name"].split(",")[0]
            self._note(("tls", src, name), f"{src} opened an encrypted connection to {name}", "tls", ts)
        if proto in CLEARTEXT and src and dst:
            client = src if local_src else dst
            what = f["http.host"].split(",")[0] if proto == "http" and f["http.host"] else self._remote_key(dst if local_src else src)
            self.cleartext[proto].add(f"{client} → {what}")
            if f["http.request.method"] or proto != "http":
                self._note((proto, client, what), f"{client} used unencrypted {CLEARTEXT[proto]} with {what}", "warning", ts)

    def _dest(self, ip: str, size: int, proto: str, device: str) -> None:
        d = self.destinations.setdefault(ip, {"ip": ip, "bytes": 0, "packets": 0, "protocols": Counter(), "devices": set()})
        d["bytes"] += size
        d["packets"] += 1
        d["protocols"][proto] += 1
        d["devices"].add(device)

    def take_rates(self) -> tuple[int, int]:
        rates = (self.second_in, self.second_out)
        self.second_in = self.second_out = 0
        return rates

    def insights(self) -> list[dict]:
        out = []
        for proto, flows in self.cleartext.items():
            out.append({"severity": "critical" if proto in ("telnet", "ftp") else "warning",
                        "title": f"Unencrypted {CLEARTEXT[proto]} traffic",
                        "detail": "Anyone on the network path can read this, including passwords. Seen: " + "; ".join(sorted(flows)[:5])
                                  + (f" (+{len(flows) - 5} more)" if len(flows) > 5 else ""),
                        "action": "Use the HTTPS/SFTP/SSH/TLS version of the service, or update the device/app."})
        if self.dns_failures:
            total = sum(self.dns_failures.values())
            top = ", ".join(n for n, _ in self.dns_failures.most_common(3))
            out.append({"severity": "info", "title": f"{total} failed DNS lookup{'s' if total > 1 else ''}",
                        "detail": f"Names that didn't resolve: {top}. A few are normal (typos, ad-blocking); many can mean "
                                  "a misconfigured device or DNS problems.", "action": ""})
        if self.dns_servers:
            servers = ", ".join(f"{s} ({self.ip_names.get(s, 'DNS')})" if s in self.ip_names else s for s, _ in self.dns_servers.most_common(4))
            out.append({"severity": "info", "title": "DNS servers in use", "detail": f"Lookups were sent to: {servers}.", "action": ""})
        busy = sorted(self.devices.items(), key=lambda kv: -(kv[1]["sent"] + kv[1]["received"]))
        total = sum(d["sent"] + d["received"] for _, d in busy) or 1
        if busy and len(busy) > 1 and (busy[0][1]["sent"] + busy[0][1]["received"]) / total > 0.6 and self.bytes > 5_000_000:
            out.append({"severity": "info", "title": f"{busy[0][0]} is using most of the bandwidth",
                        "detail": f"{(busy[0][1]['sent'] + busy[0][1]['received']) * 100 // total}% of observed traffic.", "action": ""})
        return out

    def snapshot(self, top: int = 12) -> dict:
        protos = sorted(self.protocols.items(), key=lambda kv: -kv[1][1])
        dests: dict[str, dict] = {}
        for ip, d in self.destinations.items():  # group by name when we know it
            name = self.ip_names.get(ip)
            key = name or ip
            g = dests.setdefault(key, {"name": name, "ips": set(), "bytes": 0, "packets": 0, "protocols": Counter(), "devices": set()})
            g["ips"].add(ip)
            g["bytes"] += d["bytes"]
            g["packets"] += d["packets"]
            g["protocols"].update(d["protocols"])
            g["devices"] |= d["devices"]
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "protocols": [{"key": k, "label": protocol_label(k)[0], "description": protocol_label(k)[1],
                           "packets": v[0], "bytes": v[1]} for k, v in protos],
            "devices": [{"ip": ip, "sent": d["sent"], "received": d["received"], "packets": d["packets"],
                         "top_protocol": protocol_label(d["protocols"].most_common(1)[0][0])[0] if d["protocols"] else None}
                        for ip, d in sorted(self.devices.items(), key=lambda kv: -(kv[1]["sent"] + kv[1]["received"]))[:top]],
            "destinations": [{"name": g["name"], "ips": sorted(g["ips"])[:3], "bytes": g["bytes"], "packets": g["packets"],
                              "protocol": protocol_label(g["protocols"].most_common(1)[0][0])[0], "devices": sorted(g["devices"])}
                             for g in sorted(dests.values(), key=lambda g: -g["bytes"])[:top]],
            "feed": list(self.feed)[:40],
            "insights": self.insights(),
        }


def parse_fields(line: str) -> dict | None:
    parts = line.split("\t")
    if len(parts) < len(FIELDS):
        return None
    return dict(zip(FIELDS, parts))


# --- capture ------------------------------------------------------------------------

async def capture(
    interface: str, duration: int = 60, capture_filter: str = "", save: bool = False
) -> AsyncIterator[dict]:
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("Wireshark/tshark is not installed. " + INSTALL_HELP.get(platform.system(), ""))
    duration = max(5, min(int(duration), MAX_DURATION))
    if not interface or interface.startswith("-"):
        raise RuntimeError("Choose a network interface to capture on.")
    args = [tshark, "-i", interface, "-l", "-n", "-a", f"duration:{duration}",
            "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for fld in FIELDS:
        args += ["-e", fld]
    if capture_filter.strip():
        if capture_filter.strip().startswith("-"):
            raise RuntimeError("Invalid capture filter.")
        args += ["-f", capture_filter.strip()]
    pcap_path = None
    if save:
        captures_dir().mkdir(parents=True, exist_ok=True)
        pcap_path = captures_dir() / f"subnetry-capture-{datetime.now():%Y%m%d-%H%M%S}.pcapng"
        args += ["-w", str(pcap_path), "-P"]

    analyzer = TrafficAnalyzer()
    started = time.perf_counter()
    last_emit = started
    errors: list[str] = []
    yield {"type": "start", "interface": interface, "duration": duration, "filter": capture_filter.strip()}

    def stats_event() -> dict:
        nonlocal last_emit
        now = time.perf_counter()
        bin_in, bin_out = analyzer.take_rates()
        secs = max(now - last_emit, 0.001)
        last_emit = now
        return {"type": "stats", "t": round(now - started, 1),
                "in_mbps": round(bin_in * 8 / 1e6 / secs, 3), "out_mbps": round(bin_out * 8 / 1e6 / secs, 3),
                **analyzer.snapshot()}

    async for kind, line in stream_cmd(args):
        if kind == "out":
            fields = parse_fields(line)
            if fields:
                analyzer.add(fields)
        elif kind == "err":
            # tshark also uses stderr for status chatter; keep everything else for error reporting.
            if line.strip() and not BENIGN_STDERR.search(line):
                errors.append(line.strip())
        elif kind == "exit":
            if line not in (0, None):
                msg = " ".join(errors[-5:]) or f"tshark exited with code {line}."
                everything = " ".join(errors).lower()
                if capture_filter.strip() and ("invalid capture filter" in everything or "parse filter" in everything):
                    msg = (f"\"{capture_filter.strip()}\" isn't a valid capture filter"
                           + (" (it's Wireshark display-filter syntax)" if "display filter" in everything else "")
                           + ". Press \"Filter help\" for examples, or leave the filter empty to capture everything.")
                elif "permission" in msg.lower() or "don't have permission" in msg.lower():
                    msg += " " + PERMISSION_HELP.get(platform.system(), "")
                yield {"type": "error", "message": msg}
                return
        if time.perf_counter() - last_emit >= 1.0:
            yield stats_event()
    final = stats_event()
    final["type"] = "done"
    final["seconds"] = round(time.perf_counter() - started, 1)
    if pcap_path and pcap_path.exists():
        final["pcap"] = pcap_path.name
        final["pcap_path"] = str(pcap_path)
    yield final
