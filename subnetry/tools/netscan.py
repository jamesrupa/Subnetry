"""LAN scanner: discover live hosts on a subnet and probe their open ports.

Host discovery combines three signals, because many devices ignore ping:
  1. ICMP echo via the system `ping` command (no admin rights needed).
  2. TCP connects to a few common ports. A *refused* connection still proves the
     host is up - it answered with a TCP RST.
  3. The OS ARP/neighbor table after the sweep. Probing a local address forces an
     ARP lookup, so any IP with a resolved MAC answered at layer 2.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from collections.abc import AsyncIterator
from pathlib import Path

from ..system import IS_LINUX, IS_MAC, IS_WINDOWS, run_blocking, run_cmd, safe_concurrency
from . import macvendor
from .netinfo import default_gateway, local_networks

MAX_HOSTS = 1024  # refuse anything bigger than a /22

# Common ports that answer on most device types (web UIs, SSH, file sharing, Apple devices, printers).
DISCOVERY_PORTS = [80, 443, 22, 445, 139, 53, 8080, 8443, 62078, 631, 9100]

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 515: "LPD", 548: "AFP",
    554: "RTSP", 587: "SMTP Submission", 631: "IPP/CUPS", 636: "LDAPS", 853: "DNS over TLS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MS SQL",
    1723: "PPTP", 1883: "MQTT", 1900: "UPnP", 2049: "NFS", 3000: "Dev HTTP",
    3306: "MySQL", 3389: "RDP", 5000: "UPnP/Dev HTTP", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP Alt", 8008: "HTTP Alt", 8080: "HTTP Proxy",
    8443: "HTTPS Alt", 8888: "HTTP Alt", 9100: "Printer (JetDirect)", 27017: "MongoDB",
    32400: "Plex", 49152: "UPnP", 62078: "Apple iDevice sync",
}


class ScanError(ValueError):
    pass


def resolve_target(cidr: str | None) -> ipaddress.IPv4Network:
    """Validate the requested network, defaulting to the first attached LAN."""
    if not cidr:
        nets = local_networks()
        if not nets:
            raise ScanError("No active IPv4 network found. Enter a network like 192.168.1.0/24.")
        cidr = nets[0]["network"]
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise ScanError(f"Invalid network: {exc}") from exc
    if not (net.is_private or net.is_link_local):
        raise ScanError("Only private (LAN) address ranges can be scanned.")
    if net.num_addresses > MAX_HOSTS + 2:
        raise ScanError(f"{net} is too large; use a /22 or smaller (max {MAX_HOSTS} hosts).")
    return net


def check_private_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ScanError(f"Invalid IP address: {host}") from exc
    if not (ip.is_private or ip.is_link_local):
        raise ScanError("Only private (LAN) addresses can be port-scanned.")
    return str(ip)


# --- probes -----------------------------------------------------------------------

def ping_command(ip: str, timeout_ms: int) -> list[str]:
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if IS_MAC:
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]


_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)


def parse_ping(output: str, returncode: int) -> float | None:
    """Return round-trip time in ms if the ping got a reply, else None."""
    # Windows can exit 0 on "Destination host unreachable", so require a TTL in the reply.
    if returncode != 0 or "ttl" not in output.lower():
        return None
    m = _PING_TIME.search(output)
    return float(m.group(1)) if m else 0.0


async def ping(ip: str, timeout_ms: int = 1000) -> float | None:
    res = await run_cmd(ping_command(ip, timeout_ms), timeout=timeout_ms / 1000 + 2)
    return parse_ping(res.stdout, res.returncode) if res else None


async def tcp_probe(ip: str, port: int, timeout: float) -> str:
    """'open', 'closed' (RST received - host is up) or 'filtered' (no answer)."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except ConnectionRefusedError:
        return "closed"
    except (asyncio.TimeoutError, OSError):
        return "filtered"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


async def probe_host(ip: str, timeout: float = 1.0) -> dict | None:
    t0 = time.perf_counter()
    tcp_tasks = [tcp_probe(ip, p, timeout) for p in DISCOVERY_PORTS]
    rtt, *tcp = await asyncio.gather(ping(ip, int(timeout * 1000)), *tcp_tasks)
    methods = []
    if rtt is not None:
        methods.append("icmp")
    open_ports = [p for p, state in zip(DISCOVERY_PORTS, tcp) if state == "open"]
    if any(state in ("open", "closed") for state in tcp):
        methods.append("tcp")
    if not methods:
        return None
    if rtt is None:
        rtt = round((time.perf_counter() - t0) * 1000, 2)
    return {"ip": ip, "rtt_ms": rtt, "methods": methods, "open_ports": open_ports}


# --- ARP / neighbour table --------------------------------------------------------

_IP_RE = r"(\d{1,3}(?:\.\d{1,3}){3})"
_MAC_RE = r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"


def normalize_mac(mac: str) -> str:
    return ":".join(part.zfill(2) for part in re.split("[:-]", mac)).upper()


def parse_arp_table(text: str) -> dict[str, str]:
    """IP -> MAC from `ip neigh`, `arp -a` (macOS/Windows) or /proc/net/arp output."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        if re.search(r"incomplete|FAILED", line, re.I):
            continue
        ip_m = re.search(_IP_RE, line)
        mac_m = re.search(_MAC_RE, line)
        if not (ip_m and mac_m):
            continue
        mac = normalize_mac(mac_m.group(1))
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
        table[ip_m.group(1)] = mac
    return table


async def arp_table() -> dict[str, str]:
    if IS_LINUX:
        res = await run_cmd(["ip", "neigh"])
        if res and res.ok:
            return parse_arp_table(res.stdout)
        try:
            return parse_arp_table(Path("/proc/net/arp").read_text())
        except OSError:
            return {}
    res = await run_cmd(["arp", "-a"] if IS_WINDOWS else ["arp", "-an"])
    return parse_arp_table(res.stdout) if res else {}


def is_randomized_mac(mac: str) -> bool:
    """Phones/laptops use 'private' MACs: the locally-administered bit is set."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


async def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    try:
        name = await asyncio.wait_for(run_blocking(socket.gethostbyaddr, ip), timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    return name[0]


# --- scans ------------------------------------------------------------------------

async def scan_network(
    cidr: str | None = None, timeout: float = 1.0, concurrency: int = 64
) -> AsyncIterator[dict]:
    """Sweep a subnet, yielding events: start, host, progress, done."""
    net = resolve_target(cidr)
    concurrency = safe_concurrency(len(DISCOVERY_PORTS), concurrency)
    hosts = [str(h) for h in net.hosts()] if net.prefixlen < 31 else [str(h) for h in net]
    own_ips = {n["address"] for n in local_networks()}
    gateway = await default_gateway()
    started = time.perf_counter()
    yield {"type": "start", "network": str(net), "total": len(hosts), "gateway": gateway}

    sem = asyncio.Semaphore(concurrency)
    found: dict[str, dict] = {}

    def decorate(host: dict) -> dict:
        host["is_self"] = host["ip"] in own_ips
        host["is_gateway"] = host["ip"] == gateway
        return host

    async def worker(ip: str) -> dict | None:
        async with sem:
            host = await probe_host(ip, timeout)
        if host:
            host["hostname"] = await reverse_dns(ip)
        return host

    done = 0
    for coro in asyncio.as_completed([worker(ip) for ip in hosts]):
        host = await coro
        done += 1
        if host:
            found[host["ip"]] = decorate(host)
            yield {"type": "host", "host": host}
        if done % 8 == 0 or done == len(hosts):
            yield {"type": "progress", "done": done, "total": len(hosts)}

    # Layer-2 pass: fill in MACs and catch hosts that answered ARP but nothing else.
    for ip, mac in (await arp_table()).items():
        if ipaddress.IPv4Address(ip) not in net:
            continue
        host = found.get(ip)
        if host is None:
            host = decorate({"ip": ip, "rtt_ms": None, "methods": [], "open_ports": [],
                             "hostname": await reverse_dns(ip)})
            found[ip] = host
        host["mac"] = mac
        host["vendor"] = macvendor.vendor_for(mac)
        host["mac_randomized"] = is_randomized_mac(mac)
        if "arp" not in host["methods"]:
            host["methods"].append("arp")
        yield {"type": "host", "host": host}

    yield {
        "type": "done",
        "network": str(net),
        "hosts_found": len(found),
        "seconds": round(time.perf_counter() - started, 1),
    }


def service_name(port: int) -> str:
    from .topports import SERVICES

    return COMMON_PORTS.get(port) or SERVICES.get(port, "unknown")


async def scan_ports(
    host: str, ports: list[int] | None = None, timeout: float = 0.8, concurrency: int = 100
) -> dict:
    ip = check_private_host(host)
    ports = ports or sorted(COMMON_PORTS)
    concurrency = safe_concurrency(1, concurrency)
    sem = asyncio.Semaphore(concurrency)

    async def one(port: int) -> tuple[int, str]:
        async with sem:
            return port, await tcp_probe(ip, port, timeout)

    started = time.perf_counter()
    results = await asyncio.gather(*(one(p) for p in ports))
    return {
        "host": ip,
        "scanned": len(ports),
        "seconds": round(time.perf_counter() - started, 1),
        "open": [
            {"port": p, "service": service_name(p)}
            for p, state in sorted(results) if state == "open"
        ],
    }
