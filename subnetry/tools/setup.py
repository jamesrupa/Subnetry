"""Setup: check and install the optional tools Subnetry uses (Speedtest.net CLI, Nmap, Wireshark/tshark).

How each is installed, by platform:
  Speedtest CLI  -> downloaded from Ookla straight into Subnetry's own tools folder (no admin, any OS)
  Nmap           -> Windows: winget (shows the official installer, which offers Npcap)
                    macOS: Homebrew if present, otherwise the official download page
  Wireshark      -> Windows: winget (official installer; keep Npcap + TShark ticked)
                    macOS: Homebrew in Terminal (it asks for your password), otherwise the download page
Only these fixed commands are ever run.
"""

from __future__ import annotations

import asyncio
import io
import platform
import shutil
import stat
import tarfile
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx

from ..system import IS_MAC, IS_WINDOWS, find_tool, run_cmd, stream_cmd, tools_bin_dir
from . import nmapscan, ookla, traceroute, traffic

SPEEDTEST_VERSION = "1.2.0"
SPEEDTEST_URLS = {
    ("Darwin", "arm64"): "ookla-speedtest-{v}-macosx-universal.tgz",
    ("Darwin", "x86_64"): "ookla-speedtest-{v}-macosx-universal.tgz",
    ("Windows", "AMD64"): "ookla-speedtest-{v}-win64.zip",
    ("Windows", "x86"): "ookla-speedtest-{v}-win32.zip",
    ("Linux", "x86_64"): "ookla-speedtest-{v}-linux-x86_64.tgz",
    ("Linux", "aarch64"): "ookla-speedtest-{v}-linux-aarch64.tgz",
}
SPEEDTEST_BASE = "https://install.speedtest.net/app/cli/"

WINGET_IDS = {"nmap": "Insecure.Nmap", "wireshark": "WiresharkFoundation.Wireshark"}
BREW_FORMULAS = {"nmap": ["install", "nmap"], "wireshark": ["install", "--cask", "wireshark"]}
DOWNLOAD_PAGES = {
    "speedtest": "https://www.speedtest.net/apps/cli",
    "nmap": "https://nmap.org/download.html",
    "wireshark": "https://www.wireshark.org/download.html",
}

TOOLS = {
    "speedtest": {"name": "Speedtest.net CLI", "used_by": "Speed Test and Health Check",
                  "why": "Official Speedtest.net (Ookla) measurements. Without it, Subnetry uses Cloudflare's test.",
                  "find": ookla.find_speedtest, "version_args": ["--version"]},
    "nmap": {"name": "Nmap", "used_by": "Port Scanner and the Full Scan's port check",
             "why": "The standard port scanner. Without it, the Full Scan uses Subnetry's slower built-in scanner "
                    "and the Port Scanner tab is unavailable. Also supplies the offline MAC vendor list.",
             "find": nmapscan.find_nmap, "version_args": ["--version"]},
    "wireshark": {"name": "Wireshark (tshark)", "used_by": "Traffic Analyzer",
                  "why": "Wireshark's capture engine. Needed for the Traffic Analyzer.",
                  "find": traffic.find_tshark, "version_args": ["--version"]},
}


class SetupError(Exception):
    pass


def find_brew() -> str | None:
    return find_tool("brew", ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]) if IS_MAC else None


def find_winget() -> str | None:
    if not IS_WINDOWS:
        return None
    import os

    local = os.environ.get("LOCALAPPDATA", "")
    return find_tool("winget", [str(Path(local) / "Microsoft" / "WindowsApps" / "winget.exe")])


def install_method(tool: str) -> dict:
    """How the Setup page offers to install a tool on this computer."""
    if tool == "speedtest":
        key = (platform.system(), platform.machine())
        if key in SPEEDTEST_URLS:
            return {"method": "download", "label": "Install", "note": "Downloads Ookla's official CLI (about 1 MB)."}
        return {"method": "link", "label": "Download page", "url": DOWNLOAD_PAGES[tool]}
    if IS_WINDOWS and find_winget():
        return {"method": "winget", "label": "Install",
                "note": "Opens the official installer" + (": keep Npcap and TShark ticked." if tool == "wireshark"
                                                           else ": keep Npcap ticked.")}
    if IS_MAC and find_brew():
        if tool == "wireshark":  # the cask installs ChmodBPF with sudo, so it needs a Terminal for the password
            return {"method": "brew-terminal", "label": "Install in Terminal",
                    "note": "Opens Terminal and runs Homebrew; type your Mac password when it asks."}
        return {"method": "brew", "label": "Install", "note": "Installs with Homebrew."}
    return {"method": "link", "label": "Download page", "url": DOWNLOAD_PAGES[tool],
            "note": "Download and run the official installer, then restart Subnetry."}


async def _version(path: str, args: list[str]) -> str | None:
    res = await run_cmd([path, *args], timeout=15)
    if not res or not res.ok:
        return None
    first = (res.stdout or res.stderr).strip().splitlines()
    return first[0].strip() if first else None


async def status() -> dict:
    async def one(tid: str, spec: dict) -> dict:
        path = spec["find"]()
        return {"id": tid, "name": spec["name"], "used_by": spec["used_by"], "why": spec["why"],
                "installed": bool(path), "path": path,
                "version": await _version(path, spec["version_args"]) if path else None,
                "install": None if path else install_method(tid)}

    tools = await asyncio.gather(*(one(t, s) for t, s in TOOLS.items()))
    builtin = [{"id": "traceroute", "name": "traceroute" if not IS_WINDOWS else "tracert",
                "installed": bool(traceroute.find_command()), "note": "Part of the operating system."}]
    return {"tools": tools, "builtin": builtin, "platform": platform.system(),
            "brew": bool(find_brew()), "winget": bool(find_winget())}


# --- Speedtest CLI: direct download --------------------------------------------------------------

async def install_speedtest(transport: httpx.AsyncBaseTransport | None = None) -> AsyncIterator[dict]:
    key = (platform.system(), platform.machine())
    name = SPEEDTEST_URLS.get(key)
    if not name:
        raise SetupError(f"No Speedtest CLI download for {key[0]} {key[1]}; see {DOWNLOAD_PAGES['speedtest']}.")
    url = SPEEDTEST_BASE + name.format(v=SPEEDTEST_VERSION)
    yield {"type": "log", "line": f"Downloading {url}"}
    async with httpx.AsyncClient(timeout=120, follow_redirects=True, transport=transport) as client:
        r = await client.get(url)
    if r.status_code != 200:
        raise SetupError(f"Download failed (HTTP {r.status_code}).")
    exe_name = "speedtest.exe" if key[0] == "Windows" else "speedtest"
    data = None
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            member = next((m for m in z.namelist() if m.rsplit("/", 1)[-1] == exe_name), None)
            data = z.read(member) if member else None
    else:
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as t:
            member = next((m for m in t.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] == exe_name), None)
            data = t.extractfile(member).read() if member else None
    if not data:
        raise SetupError("The download didn't contain the speedtest program.")
    dest_dir = tools_bin_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / exe_name
    tmp = dest.with_suffix(".download")
    tmp.write_bytes(data)
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp.replace(dest)
    yield {"type": "log", "line": f"Saved to {dest}"}
    version = await _version(str(dest), ["--version"])
    if not version:
        raise SetupError("The speedtest program was downloaded but doesn't run on this computer.")
    yield {"type": "log", "line": version}


# --- Nmap / Wireshark ------------------------------------------------------------------------------

def install_command(tool: str) -> list[str]:
    method = install_method(tool)["method"]
    if method == "winget":
        return [find_winget(), "install", "-e", "--id", WINGET_IDS[tool], "--interactive",
                "--accept-package-agreements", "--accept-source-agreements"]
    if method == "brew":
        return [find_brew(), *BREW_FORMULAS[tool]]
    raise SetupError(f"{TOOLS[tool]['name']} can't be installed automatically here; use its download page.")


def open_in_terminal(command: str) -> None:
    """macOS: run a command in a new Terminal window (for installers that ask for the password)."""
    script = command.replace("\\", "\\\\").replace('"', '\\"')
    import subprocess

    subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{script}"',
                      "-e", 'tell application "Terminal" to activate'])


async def install(tool: str) -> AsyncIterator[dict]:
    if tool not in TOOLS:
        raise SetupError(f"Unknown tool: {tool}")
    if TOOLS[tool]["find"]():
        yield {"type": "done", "ok": True, "message": f"{TOOLS[tool]['name']} is already installed."}
        return
    if tool == "speedtest":
        async for ev in install_speedtest():
            yield ev
    else:
        method = install_method(tool)
        if method["method"] == "brew-terminal":
            open_in_terminal(f"{shutil.which('brew') or find_brew()} {' '.join(BREW_FORMULAS[tool])}")
            yield {"type": "done", "ok": True, "pending": True,
                   "message": "Terminal opened: follow it to the end (type your Mac password when asked), then press Re-check."}
            return
        args = install_command(tool)
        yield {"type": "log", "line": "$ " + " ".join(Path(args[0]).name if i == 0 else a for i, a in enumerate(args))}
        code = None
        async for kind, line in stream_cmd(args):
            if kind == "exit":
                code = line
            elif line.strip():
                yield {"type": "log", "line": line.rstrip()}
        if code not in (0, None) and not TOOLS[tool]["find"]():
            raise SetupError(f"The installer finished with code {code}. You can also use the download page: "
                             f"{DOWNLOAD_PAGES[tool]}")
    ok = bool(TOOLS[tool]["find"]())
    yield {"type": "done", "ok": ok,
           "message": f"{TOOLS[tool]['name']} is installed." if ok else
           f"{TOOLS[tool]['name']} isn't detected yet. If an installer is still open, finish it, then press Re-check."}
