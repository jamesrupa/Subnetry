"""Quick and Full health checks: run several tools in sequence and build one report.

  quick -> speed test, Wi-Fi scan
  full  -> speed test, traceroute, network scan (saved to a file), top-1000 port scan, Wi-Fi scan

The speed test uses Speedtest.net (Ookla's CLI) and only falls back to Cloudflare when
the CLI isn't installed or fails. The port scan uses Nmap when it's installed, otherwise
the built-in scanner with the same 1000 ports.

Progress streams as events. Each tool's own events are forwarded inside a
`step_event`, so the UI can reuse its existing per-tool rendering. The final
`report` event carries the results, recommendations and score.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from ..system import raise_open_file_limit
from . import advisor, netinfo, netscan, nmapscan, ookla, speedtest, topports, traceroute, wifiscan

MODES = {
    "quick": [("speed", "Speed test"), ("wifi", "Wi-Fi scan")],
    "full": [
        ("speed", "Speed test"),
        ("trace", "Traceroute to the internet"),
        ("devices", "Network scan"),
        ("ports", "Port scan (top 1000 ports)"),
        ("wifi", "Wi-Fi scan"),
    ],
}


async def _speed(report: dict) -> AsyncIterator[dict]:
    """Speedtest.net via Ookla's CLI; Cloudflare only if the CLI is missing or fails."""
    installed = (await ookla.status())["installed"]

    async def measure(engine: str) -> AsyncIterator[dict]:
        result: dict = {}
        async for ev in speedtest.run(engine):
            if ev["type"] == "error":
                result = {"error": ev["message"]}
            elif ev["phase"] == "done":
                result = {k: v for k, v in ev.items() if k not in ("phase", "type")}
            yield ev
        report["speed"] = result or {"error": "Speed test returned no result."}

    engine = "ookla" if installed else "cloudflare"
    async for ev in measure(engine):
        yield ev
    fallback_reason = None
    if engine == "ookla" and report["speed"].get("error"):
        fallback_reason = report["speed"]["error"]
        yield {"type": "fallback", "message": "Speedtest.net didn't finish, so measuring with Cloudflare instead."}
        engine = "cloudflare"
        async for ev in measure(engine):
            yield ev
    report["speed"].update(engine_id=engine, ookla_installed=installed)
    if fallback_reason:
        report["speed"]["fallback_reason"] = fallback_reason


async def _wifi(report: dict) -> AsyncIterator[dict]:
    try:
        report["wifi"] = await wifiscan.scan_wifi()
    except wifiscan.WifiError as exc:
        report["wifi"] = {"error": str(exc), "networks": []}
    yield {"type": "result", "wifi": report["wifi"]}


async def _devices(report: dict) -> AsyncIterator[dict]:
    hosts: dict[str, dict] = {}
    net = {"hosts": []}
    async for ev in netscan.scan_network():
        if ev["type"] == "start":
            net.update(network=ev["network"], gateway=ev["gateway"])
        elif ev["type"] == "host":
            hosts[ev["host"]["ip"]] = ev["host"]
        elif ev["type"] == "error":
            net["error"] = ev["message"]
        elif ev["type"] == "done":
            net["seconds"] = ev["seconds"]
        yield ev
    net["hosts"] = sorted(hosts.values(), key=lambda h: tuple(int(o) for o in h["ip"].split(".")))
    report["network"] = net


async def _ports(report: dict) -> AsyncIterator[dict]:
    """The 1000 most common TCP ports on every device found: Nmap if installed, else built in."""
    hosts = report.get("network", {}).get("hosts", [])
    report["port_scan"] = {"engine": None, "ports": len(topports.TOP_1000), "devices": len(hosts)}
    if not hosts:
        return
    started = time.perf_counter()
    if nmapscan.find_nmap():
        try:
            async for ev in _ports_nmap(hosts):
                yield ev
            report["port_scan"].update(engine="nmap", seconds=round(time.perf_counter() - started, 1))
            return
        except netscan.ScanError as exc:
            yield {"type": "notice", "message": f"Nmap couldn't run ({exc}); using the built-in scanner instead."}
    async for ev in _ports_builtin(hosts):
        yield ev
    report["port_scan"].update(engine="built-in", seconds=round(time.perf_counter() - started, 1))


async def _ports_nmap(hosts: list[dict]) -> AsyncIterator[dict]:
    result: dict = {}
    async for ev in nmapscan.scan_hosts_top_ports([h["ip"] for h in hosts]):
        if ev["type"] == "progress":
            yield {"type": "progress", "percent": ev["percent"], "engine": "nmap"}
        elif ev["type"] == "result":
            result = ev["result"]
    found = {h["ip"]: h for h in result.get("hosts", [])}
    for done, host in enumerate(hosts, 1):
        nm = found.get(host["ip"], {"ports": []})
        host["ports"] = {
            "host": host["ip"], "scanned": len(topports.TOP_1000), "engine": "nmap",
            "open": [{"port": p["port"], "service": p.get("service") or netscan.service_name(p["port"])}
                     for p in nm["ports"] if p["protocol"] == "tcp" and p["state"] == "open"],
        }
        if not host.get("vendor") and nm.get("vendor"):
            host["vendor"] = nm["vendor"]
        yield {"type": "ports", "ip": host["ip"], "ports": host["ports"], "done": done, "total": len(hosts)}


async def _ports_builtin(hosts: list[dict]) -> AsyncIterator[dict]:
    # Up to 4 devices at a time x ~100 sockets each, fewer if the OS allows few open files (macOS: 256).
    sem = asyncio.Semaphore(max(1, min(4, (raise_open_file_limit() - 64) // 110)))

    async def one(host: dict) -> dict:
        async with sem:
            host["ports"] = await netscan.scan_ports(host["ip"], ports=topports.TOP_1000)
            host["ports"]["engine"] = "built-in"
        return host

    done = 0
    for coro in asyncio.as_completed([one(h) for h in hosts]):
        host = await coro
        done += 1
        yield {"type": "ports", "ip": host["ip"], "ports": host["ports"], "done": done, "total": len(hosts)}


TRACE_TARGET = "google.com"  # the route from this network out to a major website


async def _trace(report: dict) -> AsyncIterator[dict]:
    """The path from this network to the internet, and where delay or loss starts."""
    if not traceroute.find_command():
        report["trace"] = {"error": "traceroute isn't available on this computer.", "target": TRACE_TARGET}
        yield {"type": "error", "message": report["trace"]["error"]}
        return
    async for ev in traceroute.run(TRACE_TARGET, max_hops=20):
        if ev["type"] == "done":
            report["trace"] = {k: ev[k] for k in ("target", "target_ip", "hops", "path", "findings", "seconds")} | {"info": ev["info"]}
        yield ev
    report.setdefault("trace", {"error": "The traceroute returned no result.", "target": TRACE_TARGET})


STEPS = {"speed": _speed, "trace": _trace, "wifi": _wifi, "devices": _devices, "ports": _ports}


def new_report(mode: str) -> dict:
    return {
        "id": datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6],
        "mode": mode,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


async def run_diagnosis(mode: str = "quick") -> AsyncIterator[dict]:
    if mode not in MODES:
        raise ValueError(f"Unknown scan mode: {mode}")
    steps = MODES[mode]
    report = new_report(mode)
    started = time.perf_counter()
    report["system"] = await netinfo.overview()
    yield {"type": "plan", "mode": mode, "id": report["id"],
           "steps": [{"id": sid, "label": label} for sid, label in steps]}

    for sid, label in steps:
        yield {"type": "step", "step": sid, "status": "running"}
        status = "done"
        try:
            async for ev in STEPS[sid](report):
                yield {"type": "step_event", "step": sid, "event": ev}
        except Exception as exc:  # one failing step shouldn't sink the whole report
            status = "error"
            report.setdefault("errors", {})[sid] = str(exc)
            yield {"type": "step_event", "step": sid, "event": {"type": "error", "message": str(exc)}}
        if sid == "speed" and report.get("speed", {}).get("error"):
            status = "error"
        yield {"type": "step", "step": sid, "status": status}

    report["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["duration_s"] = round(time.perf_counter() - started, 1)
    report["recommendations"] = advisor.recommend(report)
    report["score"] = advisor.score(report["recommendations"])
    yield {"type": "report", "report": report}
