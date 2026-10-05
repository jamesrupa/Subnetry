"""Port scanning with Nmap (https://nmap.org), the standard network-mapping tool.

Nmap runs as a subprocess with an XML report written to a temp file, while its
verbose console output streams progress ("About 45% done") and live discoveries
("Discovered open port 22/tcp on 192.168.1.5") to the UI.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from dataclasses import dataclass

from ..system import IS_WINDOWS, find_tool, stream_cmd
from . import advisor
from . import netscan
from .netscan import MAX_HOSTS, ScanError

PROFILES = {
    "ping": {"label": "Host discovery", "args": ["-sn"],
             "description": "Finds which devices are up, without scanning ports. Fast."},
    "quick": {"label": "Quick (top 100 ports)", "args": ["-T4", "-F"],
              "description": "The 100 most common ports on each device. Usually under a minute."},
    "standard": {"label": "Standard (top 1000 ports + versions)", "args": ["-T4", "--top-ports", "1000", "-sV", "--version-light"],
                 "description": "Nmap's default port list, plus identifying the software behind each open port."},
    "full": {"label": "Full (all 65,535 ports + versions)", "args": ["-T4", "-p-", "-sV"],
             "description": "Every TCP port. Thorough but slow: minutes per device."},
}

INSTALL_HELP = {
    "Windows": "Download the installer from https://nmap.org/download.html (it includes Npcap), then restart Subnetry.",
    "Darwin": "Install with Homebrew: `brew install nmap` (or the installer from https://nmap.org/download.html).",
    "Linux": "Install from your package manager, e.g. `sudo apt install nmap` or `sudo dnf install nmap`.",
}

WINDOWS_PATHS = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]


def find_nmap() -> str | None:
    return find_tool("nmap", WINDOWS_PATHS if IS_WINDOWS else ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"])


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def status() -> dict:
    import platform
    path = find_nmap()
    return {
        "installed": bool(path),
        "path": path,
        "admin": is_admin(),
        "install_help": INSTALL_HELP.get(platform.system(), INSTALL_HELP["Linux"]),
        "profiles": [{"id": k, "label": v["label"], "description": v["description"]} for k, v in PROFILES.items()],
    }


MAX_PUBLIC_HOSTS = 256  # public targets: at most a /24
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")

PERMISSION_NEEDED = ("{target} is a public address. Only scan systems you own or have written permission to test, "
                     "then tick \"I own this or have permission\" and run the scan again.")


@dataclass
class Target:
    value: str          # what nmap is given: an IP, a CIDR or a hostname
    public: bool
    single: bool
    resolved: str | None = None


def _is_local(addr: ipaddress.IPv4Address | ipaddress.IPv4Network) -> bool:
    return addr.is_private or addr.is_link_local or addr.is_loopback


def check_target(target: str, authorized: bool = False) -> Target:
    """Validate an IPv4 address, CIDR range or hostname.

    Private (LAN) targets: up to a /22. Public targets: up to a /24, and only with the user's
    confirmation that they own them or have permission. The strict format checks also stop
    anything that could be read as an nmap option.
    """
    target = (target or "").strip()
    try:
        net = ipaddress.IPv4Network(target, strict=False)
    except ValueError:
        net = None
    if net is not None:
        public = not _is_local(net)
        limit = MAX_PUBLIC_HOSTS if public else MAX_HOSTS + 2
        if net.num_addresses > limit:
            raise ScanError(f"{net} is too large; use a {'/24' if public else '/22'} or smaller.")
        if public and not authorized:
            raise ScanError(PERMISSION_NEEDED.format(target=net if net.num_addresses > 1 else net.network_address))
        single = net.num_addresses == 1
        return Target(str(net.network_address) if single else str(net), public, single)
    if not _HOSTNAME.match(target):
        raise ScanError("Enter an IPv4 address, a range like 192.168.1.0/24, or a hostname like example.com.")
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
    except socket.gaierror as exc:
        raise ScanError(f"Couldn't resolve {target}: {exc.strerror or exc}") from exc
    ip = ipaddress.IPv4Address(infos[0][4][0])
    public = not _is_local(ip)
    if public and not authorized:
        raise ScanError(PERMISSION_NEEDED.format(target=f"{target} ({ip})"))
    return Target(target, public, True, str(ip))


def validate_target(target: str, authorized: bool = False) -> str:
    return check_target(target, authorized).value


def build_args(nmap: str, target: str, profile: str, os_detect: bool, scripts: bool, xml_path: str,
               skip_ping: bool = False) -> list[str]:
    if profile not in PROFILES:
        raise ScanError(f"Unknown profile: {profile}")
    args = [nmap, *PROFILES[profile]["args"]]
    if profile != "ping":
        if skip_ping:
            args.append("-Pn")  # internet hosts usually block ping; scan them anyway
        if os_detect:
            args.append("-O")
        if scripts:
            args.append("-sC")
    return args + ["-v", "--stats-every", "2s", "-oX", xml_path, target]


_PROGRESS = re.compile(r"^(?P<task>.+?) Timing: About (?P<pct>[\d.]+)% done")
_DISCOVERED = re.compile(r"^Discovered open port (?P<port>\d+)/(?P<proto>\w+) on (?P<ip>[\d.]+)")
_HOST_UP = re.compile(r"^Nmap scan report for (?:(?P<name>\S+) \()?(?P<ip>[\d.]+)\)?")


def parse_line(line: str) -> dict | None:
    if m := _PROGRESS.match(line):
        return {"type": "progress", "task": m["task"], "percent": float(m["pct"])}
    if m := _DISCOVERED.match(line):
        return {"type": "open_port", "ip": m["ip"], "port": int(m["port"]), "protocol": m["proto"]}
    if line.startswith(("Initiating ", "Completed ")):
        return {"type": "task", "message": line}
    return None


def parse_xml(text: str) -> dict:
    root = ET.fromstring(text)
    hosts = []
    for h in root.findall("host"):
        if h.find("status").get("state") != "up":
            continue
        host: dict = {"ip": None, "mac": None, "vendor": None, "hostnames": [], "ports": [], "os": []}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                host["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                host["mac"], host["vendor"] = a.get("addr"), a.get("vendor")
        host["hostnames"] = [n.get("name") for n in h.findall("hostnames/hostname")]
        for p in h.findall("ports/port"):
            state = p.find("state").get("state")
            if state not in ("open", "open|filtered"):
                continue
            svc = p.find("service")
            port = {
                "port": int(p.get("portid")), "protocol": p.get("protocol"), "state": state,
                "service": svc.get("name") if svc is not None else None,
                "product": " ".join(x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x) if svc is not None else "",
                "scripts": [{"id": s.get("id"), "output": s.get("output", "").strip()} for s in p.findall("script")],
            }
            host["ports"].append(port)
        host["os"] = [{"name": m.get("name"), "accuracy": int(m.get("accuracy", 0))} for m in h.findall("os/osmatch")][:3]
        hosts.append(host)
    hosts.sort(key=lambda x: tuple(int(o) for o in (x["ip"] or "0.0.0.0").split(".")))
    finished = root.find("runstats/finished")
    hosts_el = root.find("runstats/hosts")
    return {
        "args": root.get("args"),
        "version": root.get("version"),
        "hosts": hosts,
        "summary": finished.get("summary") if finished is not None else None,
        "elapsed": float(finished.get("elapsed", 0)) if finished is not None else None,
        "hosts_up": int(hosts_el.get("up", 0)) if hosts_el is not None else len(hosts),
        "hosts_total": int(hosts_el.get("total", 0)) if hosts_el is not None else None,
    }


def findings(result: dict, gateway: str | None = None) -> list[dict]:
    """Recommendations from the scan, using the same rules as the Health Check."""
    hosts = [{
        "ip": h["ip"], "is_gateway": h["ip"] == gateway,
        "ports": {"open": [{"port": p["port"], "service": p["service"]} for p in h["ports"] if p["protocol"] == "tcp"]},
    } for h in result["hosts"]]
    recs = advisor.port_rules(hosts)
    if gateway and any(h["is_gateway"] for h in hosts):
        recs += advisor.router_rules(next(h for h in hosts if h["is_gateway"]))
    return sorted(recs, key=lambda r: advisor.SEVERITY_ORDER[r["severity"]])


async def _stream_nmap(args: list[str], xml_path: str) -> AsyncIterator[dict]:
    """Run nmap, yielding its progress events, then {"type": "_result"} with the parsed XML.

    Removes xml_path afterwards. Raises ScanError if nmap fails.
    """
    errors: list[str] = []
    try:
        async for kind, line in stream_cmd(args):
            if kind == "out":
                ev = parse_line(line)
                if ev:
                    yield ev
            elif kind == "err" and line.strip() and not line.startswith("WARNING"):
                errors.append(line.strip())
            elif kind == "exit" and line != 0:
                msg = " ".join(errors) or f"nmap exited with code {line}"
                if "root privileges" in msg or "requires root" in msg:
                    msg += " Run Subnetry as administrator/root, or untick OS detection."
                raise ScanError(msg)
        with open(xml_path, encoding="utf-8") as f:
            result = parse_xml(f.read())
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass
    result["warnings"] = errors
    yield {"type": "_result", "result": result}


TOP_PORTS_ARGS = ["-T4", "--top-ports", "1000", "-Pn"]


async def scan_hosts_top_ports(ips: list[str]) -> AsyncIterator[dict]:
    """The Full Scan's port check: Nmap's top 1000 TCP ports on devices already found on the LAN.

    -Pn because the devices are known to be up (phones often ignore ping). Yields nmap progress
    events, then {"type": "result", "result": parse_xml(...)}.
    """
    nmap = find_nmap()
    if not nmap:
        raise ScanError("Nmap is not installed.")
    ips = [netscan.check_private_host(ip) for ip in ips]  # only ever local devices
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="subnetry-nmap-")
    os.close(fd)
    args = [nmap, *TOP_PORTS_ARGS, "-v", "--stats-every", "2s", "-oX", xml_path, *ips]
    async for ev in _stream_nmap(args, xml_path):
        yield {**ev, "type": "result"} if ev["type"] == "_result" else ev


async def run_scan(
    target: str, profile: str = "quick", os_detect: bool = False, scripts: bool = False, gateway: str | None = None,
    authorized: bool = False,
) -> AsyncIterator[dict]:
    nmap = find_nmap()
    if not nmap:
        raise ScanError("Nmap is not installed. " + status()["install_help"])
    t = await asyncio.to_thread(check_target, target, authorized)
    target = t.value
    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="subnetry-nmap-")
    os.close(fd)
    args = build_args(nmap, target, profile, os_detect, scripts, xml_path, skip_ping=t.public and t.single)
    started = time.perf_counter()
    yield {"type": "start", "target": target, "profile": profile, "public": t.public, "resolved": t.resolved,
           "command": " ".join(["nmap", *args[1:-3], target])}
    result: dict = {}
    async for ev in _stream_nmap(args, xml_path):
        if ev["type"] == "_result":
            result = ev["result"]
        else:
            yield ev
    result["findings"] = findings(result, gateway)
    result["seconds"] = round(time.perf_counter() - started, 1)
    yield {"type": "result", "result": result}
