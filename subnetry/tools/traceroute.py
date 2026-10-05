"""Traceroute: the path packets take to a destination, hop by hop, explained.

  macOS / Linux -> traceroute -n -q 3 -w 2 -m <hops> <target>
  Windows       -> tracert -d -h <hops> -w 2000 <target>

Names aren't resolved by the command (-n / -d, much faster); Subnetry looks up each hop's
reverse DNS name and its network owner (ASN, via Team Cymru's DNS service) in parallel,
then explains where delay and loss start.
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import time
from collections.abc import AsyncIterator

from ..system import IS_WINDOWS, find_tool, stream_cmd
from . import netscan

DEFAULT_HOPS = 30
MAX_HOPS = 64
PROBES = 3
CGNAT = ipaddress.ip_network("100.64.0.0/10")

INSTALL_HELP = {
    "Linux": "Install it with `sudo apt install traceroute` (or `sudo dnf install traceroute`).",
    "Darwin": "traceroute is part of macOS (/usr/sbin/traceroute); check that it hasn't been removed.",
    "Windows": "tracert is part of Windows (C:\\Windows\\System32\\tracert.exe).",
}


class TraceError(Exception):
    pass


# --- command --------------------------------------------------------------------------

def find_command() -> str | None:
    if IS_WINDOWS:
        return find_tool("tracert", [r"C:\Windows\System32\tracert.exe"])
    return find_tool("traceroute", ["/usr/sbin/traceroute", "/usr/bin/traceroute", "/sbin/traceroute"])


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if "://" in target:  # a pasted URL
        target = target.split("://", 1)[1]
    target = target.split("/")[0].strip()
    if not target or target.startswith("-") or not re.fullmatch(r"[A-Za-z0-9.:_-]{1,253}", target):
        raise TraceError("Enter a host name or IP address, e.g. google.com or 1.1.1.1.")
    return target


def build_args(exe: str, target: str, max_hops: int, windows: bool = IS_WINDOWS) -> list[str]:
    max_hops = max(1, min(int(max_hops), MAX_HOPS))
    if windows:
        return [exe, "-d", "-h", str(max_hops), "-w", "2000", target]
    return [exe, "-n", "-q", str(PROBES), "-w", "2", "-m", str(max_hops), target]


# --- parsing ----------------------------------------------------------------------------

def _ip(token: str) -> str | None:
    token = token.strip("()[]")
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


_HEADER = re.compile(r"(?:traceroute to|Tracing route to)\s+(\S+)\s*[\[(]([^\])]+)[\])]", re.I)
_WIN_HOP = re.compile(r"^\s*(\d+)\s+((?:(?:<?\d+\s*ms|\*)\s+){3})(.*)$")


def parse_header(line: str) -> dict | None:
    """traceroute to google.com (142.250.80.46), ... / Tracing route to google.com [142.250.80.46]"""
    m = _HEADER.search(line)
    if not m:
        return None
    return {"name": m[1], "ip": _ip(m[2])}


def parse_unix_line(line: str) -> dict | None:
    """' 3  10.0.0.1  9.8 ms 10.0.0.2  11.2 ms  *' -> hop; a line without a hop number continues the
    previous hop (macOS prints extra addresses that way) and comes back with hop=None."""
    m = re.match(r"^\s*(\d+)?\s+(.*\S)\s*$", line)
    if not m or not m[2]:
        return None
    tokens = m[2].split()
    ips, rtts, notes = [], [], []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "*":
            rtts.append(None)
        elif (ip := _ip(tok)) is not None:
            if ip not in ips:
                ips.append(ip)
        elif re.fullmatch(r"\d+(?:\.\d+)?", tok) and i + 1 < len(tokens) and tokens[i + 1] == "ms":
            rtts.append(float(tok))
            i += 1
        elif tok.startswith("!"):
            notes.append(tok)
        i += 1
    if m[1] is None and not ips:
        return None
    if not ips and not rtts:
        return None
    return {"hop": int(m[1]) if m[1] else None, "ips": ips, "rtts": rtts, "notes": notes}


def parse_windows_line(line: str) -> dict | None:
    """'  2    9 ms    <1 ms     *     100.64.0.1' / '  3     *        *        *     Request timed out.'"""
    m = _WIN_HOP.match(line)
    if not m:
        # "  5  192.168.1.1  reports: Destination host unreachable."
        u = re.match(r"^\s*(\d+)\s+(\S+)\s+\S+", line)
        if u and _ip(u[2]):
            return {"hop": int(u[1]), "ips": [_ip(u[2])], "rtts": [None] * PROBES, "notes": ["unreachable"]}
        return None
    rtts = []
    for tok in re.findall(r"<?\d+\s*ms|\*", m[2]):
        if tok == "*":
            rtts.append(None)
        else:
            value = float(re.search(r"\d+", tok)[0])
            rtts.append(0.5 if tok.startswith("<") else value)  # "<1 ms"
    rest = m[3].strip().split()
    ip = _ip(rest[0]) if rest else None
    return {"hop": int(m[1]), "ips": [ip] if ip else [], "rtts": rtts, "notes": []}


def summarize_hop(hop: dict) -> dict:
    got = [r for r in hop["rtts"] if r is not None]
    sent = max(len(hop["rtts"]), PROBES)
    return {
        **hop,
        "min_ms": round(min(got), 2) if got else None,
        "avg_ms": round(sum(got) / len(got), 2) if got else None,
        "max_ms": round(max(got), 2) if got else None,
        "loss_pct": round(100 * (sent - len(got)) / sent) if sent else 100,
        "responded": bool(hop["ips"]),
    }


# --- enrichment ----------------------------------------------------------------------------

def scope(ip: str) -> str:
    """'local' (your network), 'cgnat' (your ISP's shared address space) or 'public'."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4 and addr in CGNAT:
        return "cgnat"
    if addr.is_private or addr.is_link_local or addr.is_loopback:
        return "local"
    return "public"


_asn_cache: dict[str, dict | None] = {}
_asn_name_cache: dict[str, str | None] = {}


async def asn_info(ip: str) -> dict | None:
    """Network owner of a public IP, from Team Cymru's free IP-to-ASN DNS service."""
    if scope(ip) != "public":
        return None
    if ip in _asn_cache:
        return _asn_cache[ip]
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        qname = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4
    info = None
    try:
        ans = await resolver.resolve(qname, "TXT")
        # "15169 | 142.250.0.0/15 | US | arin | 2012-05-24"
        fields = [f.strip() for f in b"".join(ans[0].strings).decode().split("|")]
        asn = fields[0].split()[0]
        info = {"asn": asn, "prefix": fields[1] if len(fields) > 1 else None,
                "country": fields[2] if len(fields) > 2 else None, "org": None}
        if asn not in _asn_name_cache:
            try:
                names = await resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
                # "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
                org = b"".join(names[0].strings).decode().split("|")[-1].strip()
                org = re.sub(r",\s*[A-Z]{2}$", "", org)  # trailing country code
                _asn_name_cache[asn] = org.split(" - ", 1)[1] if " - " in org else org  # "GOOGLE - Google LLC" -> "Google LLC"
            except (dns.exception.DNSException, IndexError):
                _asn_name_cache[asn] = None
        info["org"] = _asn_name_cache[asn]
    except (dns.exception.DNSException, IndexError, ValueError):
        info = None
    _asn_cache[ip] = info
    return info


async def enrich(ip: str) -> dict:
    name, asn = await asyncio.gather(netscan.reverse_dns(ip), asn_info(ip))
    return {"ip": ip, "hostname": name, "scope": scope(ip), "asn": asn}


# --- analysis ----------------------------------------------------------------------------------

def _owner(hop: dict, info: dict[str, dict]) -> str:
    ip = hop["ips"][0] if hop["ips"] else None
    meta = info.get(ip) or {}
    if meta.get("scope") == "local":
        return "your network"
    if meta.get("scope") == "cgnat":
        return "your ISP"
    asn = meta.get("asn") or {}
    return asn.get("org") or (f"AS{asn['asn']}" if asn.get("asn") else ip or "?")


def path_summary(hops: list[dict], info: dict[str, dict]) -> list[dict]:
    """Consecutive hops grouped by network: Your network -> Comcast -> Level 3 -> Google."""
    path: list[dict] = []
    for h in hops:
        if not h["ips"]:
            continue
        owner = _owner(h, info)
        if path and path[-1]["name"] == owner:
            path[-1]["hops"].append(h["hop"])
        else:
            meta = info.get(h["ips"][0]) or {}
            path.append({"name": owner, "hops": [h["hop"]], "scope": meta.get("scope"),
                         "country": (meta.get("asn") or {}).get("country")})
    return path


def _country(hop: dict, info: dict[str, dict]) -> str | None:
    meta = info.get(hop["ips"][0]) if hop["ips"] else None
    return ((meta or {}).get("asn") or {}).get("country")


def rec(severity: str, title: str, detail: str, action: str = "") -> dict:
    return {"severity": severity, "category": "Traceroute", "title": title, "detail": detail, "action": action}


def findings(target: str, target_ip: str | None, hops: list[dict], info: dict[str, dict]) -> list[dict]:
    out = []
    answered = [h for h in hops if h["avg_ms"] is not None]
    if not hops:
        return out
    last = hops[-1]
    reached = bool(target_ip and target_ip in last["ips"]) or any(target_ip in h["ips"] for h in hops if target_ip)
    if reached:
        final = next(h for h in hops if target_ip in h["ips"])
        out.append(rec("good", f"Reached {target} in {final['hop']} hops",
                       f"Round trip to the destination: {final['avg_ms']:.0f} ms on average." if final["avg_ms"] is not None
                       else "The destination answered."))
    else:
        out.append(rec("info", f"The trace didn't get a reply from {target}",
                       "Many servers and firewalls don't answer traceroute probes, so the last hops show * even when "
                       "the site works fine.",
                       "If the website or service works normally, this is nothing to worry about. If it doesn't, "
                       "note the last hop that answered: the problem is likely just after it."))

    first = hops[0]
    first_meta = info.get(first["ips"][0]) if first["ips"] else None
    if first["avg_ms"] is not None and first_meta and first_meta.get("scope") == "local":
        if first["avg_ms"] > 15:
            out.append(rec("warning", f"Slow first hop: your router takes {first['avg_ms']:.0f} ms",
                           "The first hop is your own router, which normally answers in under 5 ms. Delay here "
                           "usually means weak Wi-Fi, interference, or a busy/overloaded router.",
                           "Move closer to the router or use Ethernet and run the trace again. If it's still slow "
                           "wired, restart the router."))
        elif first["avg_ms"] <= 5:
            out.append(rec("good", f"Your router answers quickly ({first['avg_ms']:.1f} ms)",
                           "The link between this computer and your router is healthy."))

    # Where does latency jump (and stay up)?
    best_jump = None
    for prev, cur in zip(answered, answered[1:]):
        jump = cur["min_ms"] - prev["min_ms"]
        later = [h["min_ms"] for h in answered if h["hop"] > cur["hop"]]
        persists = all(v >= prev["min_ms"] + 0.6 * jump for v in later)
        if jump > 0 and persists and (best_jump is None or jump > best_jump[0]):
            best_jump = (jump, prev, cur)
    if best_jump and best_jump[0] >= 40:
        jump, prev, cur = best_jump
        countries = {_country(h, info) for h in (prev, cur)} - {None}
        far = len(countries) > 1
        out.append(rec("info" if far else "warning",
                       f"Delay jumps by {jump:.0f} ms at hop {cur['hop']}",
                       f"Between hop {prev['hop']} ({_owner(prev, info)}) and hop {cur['hop']} ({_owner(cur, info)}) the "
                       f"round trip grows from {prev['min_ms']:.0f} to {cur['min_ms']:.0f} ms and stays there. "
                       + ("The two hops are in different countries, so this is most likely distance (light in fibre "
                          "needs about 10 ms per 1,000 km there and back)." if far else
                          "That points to a congested or long link at that point in the path."),
                       "" if far else ("If it's inside your ISP's network, run the trace at a different time of day "
                                       "and contact your ISP if it persists.")))

    # Silent hops in the middle are normal; loss that starts somewhere and continues is not.
    silent = [h["hop"] for h in hops if not h["ips"] and any(x["ips"] for x in hops if x["hop"] > h["hop"])]
    if silent:
        out.append(rec("info", f"{len(silent)} hop{'s' if len(silent) > 1 else ''} didn't respond "
                       f"({', '.join(map(str, silent[:8]))}{'…' if len(silent) > 8 else ''})",
                       "Routers often ignore or rate-limit traceroute probes while still forwarding traffic normally, "
                       "so * * * in the middle of a path that continues afterwards isn't a problem."))
    lossy = [h for h in answered if h["loss_pct"] > 0]
    if lossy and reached and hops[-1]["loss_pct"] > 0:
        start = next(h for h in answered if h["loss_pct"] > 0 and all(x["loss_pct"] > 0 for x in answered if x["hop"] >= h["hop"]))
        out.append(rec("warning", f"Packet loss from hop {start['hop']} to the destination",
                       f"Probes go missing from hop {start['hop']} ({_owner(start, info)}) onwards, all the way to the end. "
                       "Loss that carries through to the destination is real and makes calls choppy and pages slow.",
                       "Run the trace again to confirm. If the loss starts at your router or ISP, restart the modem/router "
                       "and contact your ISP with this result."))
    elif lossy:
        out.append(rec("info", "Some intermediate hops dropped probes",
                       "Loss at a hop that doesn't continue to later hops is just that router deprioritising "
                       "traceroute replies; it doesn't affect your traffic."))
    return out


# --- run -----------------------------------------------------------------------------------------

async def run(target: str, max_hops: int = DEFAULT_HOPS, resolve: bool = True) -> AsyncIterator[dict]:
    exe = find_command()
    if not exe:
        raise TraceError("traceroute isn't available. " + INSTALL_HELP.get(platform.system(), ""))
    target = validate_target(target)
    args = build_args(exe, target, max_hops)
    parse = parse_windows_line if IS_WINDOWS else parse_unix_line
    started = time.perf_counter()
    yield {"type": "start", "target": target, "max_hops": max(1, min(int(max_hops), MAX_HOPS)),
           "command": " ".join(["tracert" if IS_WINDOWS else "traceroute", *args[1:]])}

    header: dict | None = None
    hops: list[dict] = []
    raw: dict[int, dict] = {}  # hop number -> parsed line(s), before summarising
    info: dict[str, dict] = {}
    lookups: list[asyncio.Task] = []
    errors: list[str] = []

    def emit(hop_no: int) -> dict:
        h = summarize_hop(raw[hop_no])
        hops[:] = [x for x in hops if x["hop"] != hop_no] + [h]
        for ip in h["ips"]:
            if ip not in info:
                info[ip] = {"ip": ip, "scope": scope(ip)}
                if resolve:
                    lookups.append(asyncio.create_task(enrich(ip)))
        return {"type": "hop", "hop": {**h, "scopes": {ip: scope(ip) for ip in h["ips"]}}}

    async for kind, line in stream_cmd(args):
        if kind == "exit":
            if line not in (0, None) and not hops:
                msg = " ".join(errors[-3:]) or f"traceroute exited with code {line}."
                if re.search(r"unknown host|not known|resolve|could not find|cannot handle", msg, re.I):
                    msg = f"Couldn't find \"{target}\". Check the spelling, or that you're online."
                raise TraceError(msg)
            continue
        if header is None and (h := parse_header(line)):
            header = h
            yield {"type": "resolved", "name": h["name"], "ip": h["ip"]}
            continue
        if kind == "err":
            if line.strip():
                errors.append(line.strip())
            continue
        parsed = parse(line)
        if not parsed:
            if re.search(r"unable to resolve|could not find", line, re.I):
                errors.append(line.strip())
            continue
        if parsed["hop"] is None:  # macOS continuation line: more addresses/times for the last hop
            if not hops:
                continue
            last = raw[hops[-1]["hop"]]
            last["ips"] += [ip for ip in parsed["ips"] if ip not in last["ips"]]
            last["rtts"] += parsed["rtts"]
            yield emit(hops[-1]["hop"])
        else:
            raw[parsed["hop"]] = parsed
            yield emit(parsed["hop"])
        for t in [t for t in lookups if t.done()]:
            lookups.remove(t)
            meta = t.result()
            info[meta["ip"]] = meta
            yield {"type": "info", "info": meta}

    if lookups:
        await asyncio.wait(lookups, timeout=8)
    for t in lookups:
        if t.done():
            meta = t.result()
            info[meta["ip"]] = meta
            yield {"type": "info", "info": meta}
        else:
            t.cancel()
    hops.sort(key=lambda h: h["hop"])
    target_ip = header["ip"] if header else _ip(target)
    yield {
        "type": "done",
        "target": target,
        "target_ip": target_ip,
        "hops": hops,
        "info": info,
        "path": path_summary(hops, info),
        "findings": findings(target, target_ip, hops, info),
        "seconds": round(time.perf_counter() - started, 1),
    }
