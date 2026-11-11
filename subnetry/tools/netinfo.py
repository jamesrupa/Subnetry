"""Information about this machine's network setup: interfaces, gateway, DNS."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import struct
from pathlib import Path

import httpx
import psutil

from ..system import IS_LINUX, IS_MAC, IS_WINDOWS, run_cmd

_LINK_AF = getattr(psutil, "AF_LINK", getattr(socket, "AF_PACKET", -1))


def interfaces() -> list[dict]:
    """All network interfaces with their addresses and link status."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    result = []
    for name, entries in addrs.items():
        st = stats.get(name)
        iface = {
            "name": name,
            "is_up": bool(st and st.isup),
            "speed_mbps": (st.speed or None) if st else None,
            "mtu": st.mtu if st else None,
            "mac": None,
            "ipv4": [],
            "ipv6": [],
        }
        for a in entries:
            if a.family == socket.AF_INET:
                entry = {"address": a.address, "netmask": a.netmask}
                if a.netmask:
                    entry["network"] = str(ipaddress.IPv4Interface(f"{a.address}/{a.netmask}").network)
                iface["ipv4"].append(entry)
            elif a.family == socket.AF_INET6:
                iface["ipv6"].append({"address": a.address.split("%")[0]})
            elif a.family == _LINK_AF and a.address and a.address != "00:00:00:00:00:00":
                iface["mac"] = a.address.replace("-", ":").upper()
        result.append(iface)
    result.sort(key=lambda i: (not i["is_up"], not i["ipv4"], i["name"]))
    return result


# Adapters that belong to VPNs, virtual machines, containers or phone tethering, not the real LAN.
_VIRTUAL_IFACE = re.compile(
    r"^(utun|tun|tap|ppp|ipsec|gif|stf|bridge|vmnet|vnic|vboxnet|docker|br-|veth|virbr|llw|awdl|anpi|ap\d|zt|tailscale|wg)"
    r"|vethernet|virtualbox|vmware|hyper-v|host-only|wsl|loopback|bluetooth|tailscale|zerotier|wireguard|vpn|openvpn|teredo|isatap",
    re.I,
)


def primary_ipv4() -> str | None:
    """The local address the OS uses to reach the internet (connecting a UDP socket sends nothing)."""
    for probe in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((probe, 53))
                addr = s.getsockname()[0]
        except OSError:
            continue
        if addr and not addr.startswith(("0.", "127.")):
            return addr
    return None


def rank_networks(nets: list[dict], primary: str | None) -> list[dict]:
    """Put the real LAN first: the one carrying internet traffic, then physical adapters, then virtual ones."""
    def key(n: dict) -> tuple:
        net = ipaddress.IPv4Network(n["network"])
        return (
            n["address"] != primary,
            bool(_VIRTUAL_IFACE.search(n["interface"])),
            not net.is_private,
            net.prefixlen >= 31,
        )
    return sorted(nets, key=key)


def local_networks() -> list[dict]:
    """IPv4 networks this machine is directly attached to (candidates for a LAN scan), best guess first."""
    nets = []
    for iface in interfaces():
        if not iface["is_up"]:
            continue
        for a in iface["ipv4"]:
            if "network" not in a:
                continue
            ip = ipaddress.IPv4Address(a["address"])
            if ip.is_loopback or ip.is_link_local:
                continue
            nets.append({"interface": iface["name"], "address": a["address"], "network": a["network"]})
    return rank_networks(nets, primary_ipv4())


def parse_proc_net_route(text: str) -> str | None:
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":
            return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    return None


def parse_windows_route_print(text: str) -> str | None:
    m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text, re.M)
    return m.group(1) if m else None


async def default_gateway() -> str | None:
    if IS_LINUX:
        try:
            return parse_proc_net_route(Path("/proc/net/route").read_text())
        except OSError:
            return None
    if IS_MAC:
        res = await run_cmd(["route", "-n", "get", "default"])
        if res:
            m = re.search(r"gateway:\s*(\S+)", res.stdout)
            return m.group(1) if m else None
        return None
    if IS_WINDOWS:
        res = await run_cmd(["route", "print", "-4", "0.0.0.0"])
        return parse_windows_route_print(res.stdout) if res else None
    return None


def parse_ipconfig_dns(text: str) -> list[str]:
    """Pull DNS servers out of Windows `ipconfig /all` (continuation lines are indented IPs)."""
    servers: list[str] = []
    collecting = False
    for line in text.splitlines():
        if "DNS Servers" in line and ":" in line:
            collecting = True
            value = line.split(":", 1)[1].strip()
        elif collecting and re.match(r"^\s+[0-9a-fA-F:.%]+\s*$", line):
            value = line.strip()
        else:
            collecting = False
            continue
        if value and value not in servers:
            servers.append(value)
    return servers


async def dns_servers() -> list[str]:
    if IS_WINDOWS:
        res = await run_cmd(["ipconfig", "/all"])
        return parse_ipconfig_dns(res.stdout) if res else []
    if IS_MAC:
        res = await run_cmd(["scutil", "--dns"])
        if res:
            return list(dict.fromkeys(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", res.stdout)))
    try:
        text = Path("/etc/resolv.conf").read_text()
    except OSError:
        return []
    return re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)


async def overview() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "gateway": await default_gateway(),
        "dns_servers": await dns_servers(),
        "interfaces": interfaces(),
        "networks": local_networks(),
    }


async def public_ip() -> dict:
    """Ask a public service which address our traffic appears to come from."""
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get("https://api.ipify.org", params={"format": "json"})
        r.raise_for_status()
        return {"ip": r.json().get("ip")}
