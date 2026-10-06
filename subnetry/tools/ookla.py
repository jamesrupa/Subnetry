"""Speed test via the official Speedtest® CLI by Ookla (speedtest.net).

The CLI is run with `--format=jsonl --progress=yes`, which prints one JSON
object per line while the test runs:

  testStart -> server and ISP
  ping      -> {"ping": {"latency", "jitter", "progress"}}
  download  -> {"download": {"bandwidth" (bytes/s), "bytes", "elapsed" (ms), "progress"}}
  upload    -> same shape as download
  result    -> final numbers, packet loss and a shareable speedtest.net result URL
  log       -> messages; level "error" means the test failed

These are translated into the same event shape as the built-in Cloudflare test,
so the UI and Health Check work with either engine.
"""

from __future__ import annotations

import json
import platform
from collections.abc import AsyncIterator

from ..system import IS_MAC, IS_WINDOWS, find_tool, run_cmd, stream_cmd

INSTALL_HELP = {
    "Darwin": "Install with Homebrew: `brew tap teamookla/speedtest`, then `brew trust teamookla/speedtest` (newer Homebrew versions require approving third-party taps), then `brew install speedtest --force`. Restart Subnetry afterwards.",
    "Windows": "Install with `winget install Ookla.Speedtest.CLI` (or download from https://www.speedtest.net/apps/cli), then restart Subnetry.",
    "Linux": "Follow the instructions at https://www.speedtest.net/apps/cli (packages for Debian/Ubuntu and Fedora), then restart Subnetry.",
}
TERMS = "https://www.speedtest.net/about/eula"
PRIVACY = "https://www.speedtest.net/about/privacy"

_cached: dict | None = None


def find_speedtest() -> str | None:
    if IS_WINDOWS:
        extra = [r"C:\Program Files\Ookla\Speedtest CLI\speedtest.exe"]
    elif IS_MAC:
        extra = ["/opt/homebrew/bin/speedtest", "/usr/local/bin/speedtest"]
    else:
        extra = []
    from ..system import tools_bin_dir

    extra = [str(tools_bin_dir() / ("speedtest.exe" if IS_WINDOWS else "speedtest")), *extra]
    return find_tool("speedtest", extra)


async def status(refresh: bool = False) -> dict:
    """Is the *Ookla* CLI installed? (The unrelated Python `speedtest-cli` also installs a `speedtest` command.)"""
    global _cached
    if _cached is not None and not refresh:
        return _cached
    path = find_speedtest()
    info = {"installed": False, "path": path, "version": None,
            "install_help": INSTALL_HELP.get(platform.system(), INSTALL_HELP["Linux"]),
            "terms_url": TERMS, "privacy_url": PRIVACY}
    if path:
        res = await run_cmd([path, "--version"], timeout=10)
        first = (res.stdout.strip().splitlines() or [""])[0] if res else ""
        if "ookla" in first.lower():
            info.update(installed=True, version=first)
        elif first:
            info["conflict"] = (f"`{path}` is a different tool ({first}), not Ookla's Speedtest CLI. "
                                "Uninstall it (e.g. `pip uninstall speedtest-cli` or `brew uninstall speedtest-cli`) "
                                "and install the official CLI.")
    _cached = info
    return info


def base_args(path: str) -> list[str]:
    # Running the CLI requires accepting Ookla's license; the UI shows the terms next to the button.
    return [path, "--accept-license", "--accept-gdpr"]


def parse_servers(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [{"id": s.get("id"), "name": s.get("name"), "location": s.get("location"), "country": s.get("country"),
             "host": s.get("host")} for s in data.get("servers", [])]


async def servers() -> list[dict]:
    """Nearby servers, closest first."""
    path = find_speedtest()
    if not path:
        return []
    res = await run_cmd([*base_args(path), "--servers", "--format=json"], timeout=30)
    return parse_servers(res.stdout) if res and res.ok else []


def mbps(bandwidth_bytes_per_s) -> float:
    return round((bandwidth_bytes_per_s or 0) * 8 / 1e6, 2)


def server_info(s: dict | None) -> dict | None:
    if not s:
        return None
    return {"id": s.get("id"), "name": s.get("name"), "location": s.get("location"),
            "country": s.get("country"), "host": s.get("host")}


class OoklaTranslator:
    """Turns Ookla JSONL lines into Subnetry speed-test events."""

    def __init__(self) -> None:
        self.started: set[str] = set()
        self.latency_done = False

    def _start(self, phase: str) -> list[dict]:
        if phase in self.started:
            return []
        self.started.add(phase)
        return [{"phase": phase, "type": "start"}]

    def feed(self, line: str) -> list[dict]:
        line = line.strip()
        if not line.startswith("{"):
            return []
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return []
        kind = d.get("type")
        out: list[dict] = []
        if kind == "testStart":
            out.append({"phase": "info", "type": "server", "server": server_info(d.get("server")), "isp": d.get("isp")})
        elif kind == "ping":
            p = d.get("ping", {})
            out += self._start("latency")
            if p.get("latency") is not None:
                out.append({"phase": "latency", "type": "sample", "ms": round(p["latency"], 2)})
        elif kind in ("download", "upload"):
            if "latency" in self.started and not self.latency_done:
                self.latency_done = True  # Ookla's final ping numbers only come with the result
            out += self._start(kind)
            x = d.get(kind, {})
            if x.get("elapsed") is not None and x.get("bandwidth") is not None:
                out.append({"phase": kind, "type": "sample", "t": round(x["elapsed"] / 1000, 2),
                            "mbps": mbps(x["bandwidth"]), "progress": x.get("progress")})
        elif kind == "result":
            ping = d.get("ping", {})
            summary = {
                "latency_ms": round(ping.get("latency") or 0, 2),
                "jitter_ms": round(ping.get("jitter") or 0, 2),
                "download_mbps": mbps(d.get("download", {}).get("bandwidth")),
                "upload_mbps": mbps(d.get("upload", {}).get("bandwidth")),
            }
            out.append({"phase": "latency", "type": "result", "latency_ms": summary["latency_ms"], "jitter_ms": summary["jitter_ms"]})
            out.append({"phase": "download", "type": "result", "mbps": summary["download_mbps"]})
            out.append({"phase": "upload", "type": "result", "mbps": summary["upload_mbps"]})
            iface = d.get("interface", {})
            out.append({
                "phase": "done", "type": "result", **summary,
                "packet_loss": d.get("packetLoss"),
                "isp": d.get("isp"),
                "server": server_info(d.get("server")),
                "result_url": (d.get("result") or {}).get("url"),
                "external_ip": iface.get("externalIp"),
                "is_vpn": iface.get("isVpn"),
                "engine": "Speedtest.net (Ookla)",
            })
        elif kind == "log" and str(d.get("level", "")).lower() == "error":
            out.append({"phase": "error", "type": "error", "message": d.get("message", "Speedtest failed.")})
        return out


async def run(server_id: int | None = None) -> AsyncIterator[dict]:
    st = await status()
    if not st["installed"]:
        yield {"phase": "error", "type": "error",
               "message": st.get("conflict") or "Ookla's Speedtest CLI is not installed. " + st["install_help"]}
        return
    args = [*base_args(st["path"]), "--format=jsonl", "--progress=yes"]
    if server_id:
        args.append(f"--server-id={int(server_id)}")
    tr = OoklaTranslator()
    errors: list[str] = []
    finished = False
    async for kind, line in stream_cmd(args):
        if kind == "out":
            for ev in tr.feed(line):
                if ev["type"] == "error":
                    errors.append(ev["message"])
                    continue
                if ev["phase"] == "done":
                    finished = True
                yield ev
        elif kind == "err":
            # stderr carries errors as JSON log lines or plain text, depending on the failure
            evs = tr.feed(line)
            errors += [e["message"] for e in evs if e["type"] == "error"] or ([line.strip()] if line.strip() else [])
        elif kind == "exit" and not finished:
            msg = "; ".join(dict.fromkeys(errors)) or f"Speedtest CLI exited with code {line}."
            yield {"phase": "error", "type": "error", "message": msg}
