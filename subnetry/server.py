"""FastAPI app: JSON/SSE API for each tool plus the static web UI.

Long-running tools (speed test, network scan) stream Server-Sent Events so the
browser can show live progress through a plain `EventSource`.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .tools import dashboard, diagnose, dnsinfo, ipinfo, macos, macvendor, portref, subnetcalc, netinfo, netscan, nmapscan, ookla, report, speedtest, traffic, wifimonitor, wifiscan

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Subnetry", version=__version__)


@app.middleware("http")
async def block_cross_site(request: Request, call_next):
    # The API runs scans on request, so refuse calls initiated by other websites.
    if request.headers.get("sec-fetch-site") == "cross-site":
        return JSONResponse({"detail": "Cross-site requests are not allowed."}, status_code=403)
    return await call_next(request)


@app.middleware("http")
async def revalidate_ui_files(request: Request, call_next):
    """Make browsers (and the desktop window, which keeps its cache between runs) check for a newer
    page and scripts on every load, so an update shows up straight away. Unchanged files still come
    back as a quick 304 Not Modified."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


def sse(events: AsyncIterator[dict]) -> StreamingResponse:
    async def stream():
        try:
            async for ev in events:
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as exc:  # report the failure to the UI instead of dropping the stream
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)})}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --- API --------------------------------------------------------------------------

@app.get("/api/overview")
async def overview():
    return await netinfo.overview()


@app.get("/api/public-ip")
async def public_ip():
    try:
        return await netinfo.public_ip()
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Could not determine public IP: {exc}") from exc


@app.get("/api/dashboard")
async def dashboard_summary():
    return await dashboard.summary()


@app.get("/api/dashboard/live")
async def dashboard_live(interval: float = Query(2.0, ge=1, le=30)):
    return sse(dashboard.live(interval=interval))


# --- Toolkit: subnet calculator, MAC vendors, port reference, DNS ---------------------------

@app.get("/api/subnet")
async def subnet(q: str, split_prefix: int | None = None):
    try:
        result = subnetcalc.calculate(q)
        if split_prefix is not None:
            result["split"] = subnetcalc.split(q, split_prefix)
        return result
    except subnetcalc.SubnetError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/subnet/summarize")
async def subnet_summarize(q: str):
    try:
        return subnetcalc.summarize(q)
    except subnetcalc.SubnetError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/mac")
async def mac_lookup(q: str):
    return await asyncio.to_thread(macvendor.lookup, q)


@app.get("/api/mac/status")
async def mac_status():
    return await asyncio.to_thread(macvendor.status)


@app.post("/api/mac/update")
async def mac_update():
    try:
        return await macvendor.update_from_ieee()
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.get("/api/portref")
async def port_reference(q: str = "", category: str = ""):
    return {"ports": portref.search(q, category), "categories": portref.CATEGORIES, "ranges": portref.RANGES,
            "total": len(portref.PORTS)}


@app.get("/api/dns")
async def dns_lookup(q: str, resolver: str = Query("system", pattern="^(system|cloudflare|google|quad9)$")):
    try:
        return await dnsinfo.lookup(q, resolver)
    except dnsinfo.DnsError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/dns/explainers")
async def dns_explainers():
    return {"explainers": dnsinfo.EXPLAINERS, "resolvers": {k: v[0] for k, v in dnsinfo.RESOLVERS.items()}}


@app.get("/api/speedtest")
async def run_speedtest(
    engine: str = Query("auto", pattern="^(auto|ookla|cloudflare)$"),
    server_id: int | None = None,
    duration: float = Query(8.0, ge=2, le=30),
    streams: int = Query(4, ge=1, le=16),
):
    async def run():
        async for ev in speedtest.run(engine, server_id, duration=duration, streams=streams):
            if ev.get("phase") == "done":
                dashboard.record_speed(ev)
            yield ev
    return sse(run())


@app.get("/api/speedtest/status")
async def speedtest_status():
    return {"ookla": await ookla.status(refresh=True)}


@app.get("/api/speedtest/servers")
async def speedtest_servers():
    return {"servers": await ookla.servers()}


@app.get("/api/scan")
async def scan(cidr: str | None = None, timeout: float = Query(1.0, ge=0.2, le=5)):
    # Validation errors (bad CIDR, public range, too large) arrive as an "error" event,
    # since EventSource can't read the body of an HTTP error response.
    async def run():
        async for ev in netscan.scan_network(cidr, timeout=timeout):
            if ev["type"] == "done":
                dashboard.record_devices(ev["network"], ev["hosts_found"])
            yield ev
    return sse(run())


@app.get("/api/ports")
async def ports(host: str):
    try:
        return await netscan.scan_ports(host)
    except netscan.ScanError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/wifi")
async def wifi():
    try:
        return await wifiscan.scan_wifi()
    except wifiscan.WifiError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/api/ipinfo")
async def ip_info(ip: str | None = None):
    try:
        return await ipinfo.lookup(ip or None)
    except ipinfo.IpInfoError as exc:
        raise HTTPException(400 if ip else 502, str(exc)) from exc


@app.get("/api/macos/location")
async def macos_location():
    return await asyncio.to_thread(macos.location_status)


@app.post("/api/macos/location/request")
async def macos_location_request():
    """Ask macOS for Location access (shows the system prompt the first time)."""
    return await asyncio.to_thread(macos.request_location)


@app.get("/api/wifi/monitor")
async def wifi_monitor(interval: float = Query(1.0, ge=0.5, le=10), scan_every: float = Query(30, ge=10, le=300)):
    return sse(wifimonitor.monitor(interval=interval, scan_every=scan_every))


@app.get("/api/nmap/status")
async def nmap_status():
    return nmapscan.status()


@app.get("/api/nmap/scan")
async def nmap_scan(target: str, profile: str = "quick", os_detect: bool = False, scripts: bool = False,
                    authorized: bool = False):
    async def run():
        gateway = await netinfo.default_gateway()
        async for ev in nmapscan.run_scan(target, profile, os_detect, scripts, gateway, authorized):
            yield ev
    return sse(run())


@app.get("/api/traffic/status")
async def traffic_status():
    return await traffic.status()


@app.get("/api/traffic/capture")
async def traffic_capture(
    interface: str,
    duration: int = Query(60, ge=5, le=traffic.MAX_DURATION),
    filter: str = "",
    save: bool = False,
):
    return sse(traffic.capture(interface, duration, filter, save))


@app.get("/api/traffic/captures/{name}")
async def traffic_download(name: str):
    if not re.fullmatch(r"subnetry-capture-[\d-]+\.pcapng", name):
        raise HTTPException(400, "Invalid capture name.")
    path = traffic.captures_dir() / name
    if not path.is_file():
        raise HTTPException(404, "Capture not found.")
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@app.get("/api/diagnose")
async def run_diagnosis(mode: str = Query("quick", pattern="^(quick|full)$")):
    return sse(_diagnose_and_store(mode))


# Recent reports, kept in memory so the UI can download them in any format.
REPORTS: dict[str, dict] = {}
MAX_REPORTS = 20


async def _diagnose_and_store(mode: str) -> AsyncIterator[dict]:
    async for ev in diagnose.run_diagnosis(mode):
        if ev["type"] == "report":
            rep = ev["report"]
            dashboard.record_health(rep)
            if rep.get("speed") and not rep["speed"].get("error"):
                dashboard.record_speed(rep["speed"])
            if rep.get("network") and not rep["network"].get("error"):
                dashboard.record_devices(rep["network"].get("network"), len(rep["network"].get("hosts", [])))
            REPORTS[rep["id"]] = rep
            while len(REPORTS) > MAX_REPORTS:
                REPORTS.pop(next(iter(REPORTS)))
            if mode == "full":  # full scans are exported to the reports folder automatically
                try:
                    rep["saved_files"] = report.save(rep, report.FULL_SCAN_FILES)
                except OSError as exc:
                    rep["save_error"] = f"Could not save the report: {exc}"
        yield ev


@app.get("/api/reports/{report_id}/export")
async def export_report(report_id: str, format: str = Query("html")):
    rep = REPORTS.get(report_id)
    if rep is None:
        raise HTTPException(404, "Report not found. Reports are kept in memory until the app restarts.")
    if format not in report.EXPORTS:
        raise HTTPException(400, f"Format must be one of: {', '.join(report.EXPORTS)}")
    media_type, ext = report.EXPORTS[format]
    return Response(
        report.render(rep, format),
        media_type=f"{media_type}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{report.filename(rep, ext)}"'},
    )


# --- UI ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
