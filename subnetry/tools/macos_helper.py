"""Build and drive "Subnetry Wi-Fi Helper", a tiny macOS app that reads Wi-Fi details.

Why a separate app: on macOS 14+ Wi-Fi names (SSIDs) and access-point IDs (BSSIDs)
require Location Services permission, and macOS only keeps that permission for a
real app bundle that declares why it needs location (NSLocation*UsageDescription).
Homebrew's Python isn't such an app, so its Location toggle keeps switching off.

The helper's Swift source ships with Subnetry. On first use it's compiled with the
Xcode Command Line Tools (`swiftc`), ad-hoc code-signed, and stored in
~/Library/Application Support/Subnetry/. Permission is granted to the helper once
and sticks, because the helper's identity doesn't change until its source does.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from ..system import IS_MAC, CmdResult, run_cmd_sync

SOURCE_DIR = Path(__file__).resolve().parent.parent / "macos_helper"
APP_NAME = "Subnetry Wi-Fi Helper.app"


def _prebuilt() -> Path:
    """The helper built at release time by packaging/macos/build.sh, inside Subnetry.app's Resources,
    so users of the downloadable app don't need Apple's developer tools."""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent.parent / "Resources" / APP_NAME
    return SOURCE_DIR / "prebuilt" / APP_NAME


PREBUILT = _prebuilt()
EXECUTABLE = "subnetry-wifi-helper"
BAND = {1: "2.4 GHz", 2: "5 GHz", 3: "6 GHz"}

INSTALL_TOOLS = ("Install Apple's free command-line developer tools with `xcode-select --install` "
                 "(they're usually already there if you use Homebrew), then try again.")


class HelperUnavailable(RuntimeError):
    pass


def support_dir() -> Path:
    return Path(os.environ.get("SUBNETRY_SUPPORT_DIR") or Path.home() / "Library" / "Application Support" / "Subnetry")


def app_path() -> Path:
    return support_dir() / APP_NAME


def source_hash() -> str:
    h = hashlib.sha256()
    for name in ("WiFiHelper.swift", "Info.plist"):
        h.update((SOURCE_DIR / name).read_bytes())
    return h.hexdigest()[:16]


_build_lock = threading.Lock()


def _find_swiftc() -> str | None:
    found = shutil.which("swiftc")
    if found:
        return found
    res = run_cmd_sync(["xcrun", "--find", "swiftc"], timeout=30)
    return res.stdout.strip() if res and res.ok and res.stdout.strip() else None


def _native_prefix() -> list[str]:
    """["arch", "-arm64"] when this Python runs under Rosetta on an Apple Silicon Mac.

    Child processes inherit Rosetta, so swiftc would start as x86_64 and fail to load its
    arm64-only build libraries ("incompatible architecture (have 'arm64', need 'x86_64')").
    """
    res = run_cmd_sync(["sysctl", "-n", "sysctl.proc_translated"], timeout=10)
    return ["arch", "-arm64"] if res and res.ok and res.stdout.strip() == "1" else []


COMPILER_MISMATCH = ("This usually means Apple's command-line tools are out of step with macOS. Update them in "
                     "System Settings > General > Software Update, or reinstall them with "
                     "`sudo rm -rf /Library/Developer/CommandLineTools` and then `xcode-select --install`.")
CLT_SDKS = Path("/Library/Developer/CommandLineTools/SDKs")


def _sdk_candidates() -> list[str]:
    """Versioned macOS SDKs, newest first (MacOSX.sdk is just a link to one of them)."""
    def version(p: Path) -> tuple:
        digits = p.name.removeprefix("MacOSX").removesuffix(".sdk")
        return tuple(int(x) for x in digits.split(".") if x.isdigit())
    try:
        sdks = [p for p in CLT_SDKS.glob("MacOSX*.sdk") if p.name != "MacOSX.sdk" and not p.is_symlink()]
    except OSError:
        return []
    return [str(p) for p in sorted(sdks, key=version, reverse=True)]


def _error_summary(text: str) -> str:
    """The compiler's "error:" lines, not the end of a 5 KB command line."""
    errors = list(dict.fromkeys(line.strip() for line in (text or "").splitlines() if "error:" in line))
    return " ".join(errors[:3])[:600] if errors else (text or "swiftc did not run").strip()[-600:]


def _compile(swiftc: str, output: Path) -> CmdResult:
    """Compile the helper with the default SDK; if that fails, retry with each installed SDK.

    A compiler that's older than the default SDK can't read that SDK's Swift modules
    ("this SDK is not supported by the compiler"), but an older SDK alongside it usually works.
    """
    base = [*_native_prefix(), swiftc, "-O", str(SOURCE_DIR / "WiFiHelper.swift"), "-o", str(output),
            "-framework", "CoreWLAN", "-framework", "CoreLocation", "-framework", "AppKit"]
    first = res = run_cmd_sync(base, timeout=300)
    for sdk in _sdk_candidates():
        if res and res.ok:
            break
        res = run_cmd_sync([*base, "-sdk", sdk], timeout=300)
    if res and res.ok:
        return res
    return first or CmdResult(1, "", "swiftc did not run")  # report the default SDK's error


def ensure_built() -> Path:
    """Return the helper app, compiling it first if it's missing or its source changed."""
    if not IS_MAC:
        raise HelperUnavailable("The Wi-Fi helper app is only needed on macOS.")
    app = app_path()
    stamp = support_dir() / "wifi-helper.version"
    wanted = source_hash()
    with _build_lock:
        if (app / "Contents" / "MacOS" / EXECUTABLE).is_file() and stamp.is_file() and stamp.read_text().strip() == wanted:
            return app
        if PREBUILT.is_dir():  # the packaged app ships a helper built (and ad-hoc signed) at release time
            support_dir().mkdir(parents=True, exist_ok=True)
            if app.exists():
                shutil.rmtree(app)
            shutil.copytree(PREBUILT, app, symlinks=True)
            stamp.write_text(wanted)
            return app
        swiftc = _find_swiftc()
        if not swiftc:
            raise HelperUnavailable("Building the Wi-Fi helper needs Apple's Swift compiler. " + INSTALL_TOOLS)
        build_root = Path(tempfile.mkdtemp(prefix="subnetry-helper-"))
        try:
            staged = build_root / APP_NAME
            (staged / "Contents" / "MacOS").mkdir(parents=True)
            shutil.copy(SOURCE_DIR / "Info.plist", staged / "Contents" / "Info.plist")
            res = _compile(swiftc, staged / "Contents" / "MacOS" / EXECUTABLE)
            if not res.ok:
                raise HelperUnavailable(f"Couldn't build the Wi-Fi helper: {_error_summary(res.stderr or res.stdout)} "
                                        + COMPILER_MISMATCH)
            # Ad-hoc signature: gives the app a stable identity so macOS remembers its permission.
            sign = run_cmd_sync(["codesign", "--force", "--deep", "--sign", "-", str(staged)], timeout=60)
            if not sign or not sign.ok:
                raise HelperUnavailable(f"Couldn't sign the Wi-Fi helper: {(sign.stderr if sign else '').strip()}")
            support_dir().mkdir(parents=True, exist_ok=True)
            if app.exists():
                shutil.rmtree(app)
            shutil.move(str(staged), str(app))
            stamp.write_text(wanted)
        finally:
            shutil.rmtree(build_root, ignore_errors=True)
        return app


def _open_args(app: Path, mode: str, *args: str, background: bool = True) -> list[str]:
    # `open` launches it as its own app (so macOS attributes the permission to the helper, not Python).
    return ["open", "-W", "-n", *(["-g"] if background else []), "-a", str(app), "--args", mode, *args]


def call(mode: str, timeout: float = 30, background: bool = True) -> dict:
    """Run the helper once and return the JSON it wrote."""
    app = ensure_built()
    fd, out = tempfile.mkstemp(prefix="subnetry-wifi-", suffix=".json")
    os.close(fd)
    os.remove(out)
    try:
        res = run_cmd_sync(_open_args(app, mode, out, background=background), timeout=timeout)
        if res is None:
            raise HelperUnavailable("The Wi-Fi helper didn't respond in time.")
        try:
            with open(out, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            detail = (res.stderr or "").strip()
            raise HelperUnavailable(f"The Wi-Fi helper returned no data. {detail}".strip()) from exc
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


# --- conversions ----------------------------------------------------------------------

def to_network(d: dict, in_use: bool | None = None) -> dict:
    from .macos import is_redacted
    from .wifiscan import make_network

    ssid = d.get("ssid")
    redacted = is_redacted(ssid)
    return make_network(
        None if redacted else ssid,
        d.get("bssid"),
        signal_dbm=d.get("rssi"),
        channel=d.get("channel") or None,
        band=BAND.get(d.get("band")),
        security=d.get("security"),
        in_use=bool(d.get("current")) if in_use is None else in_use,
        noise_dbm=d.get("noise") or None,
        redacted=redacted,
    )


def networks_from_scan(data: dict) -> list[dict]:
    nets = [to_network(n) for n in data.get("networks", [])]
    cur = data.get("current")
    if cur and not any(n["in_use"] for n in nets):
        # Without a BSSID to match on, find the connected network by name and channel, else add it.
        match = next((n for n in nets if cur.get("ssid") and n["ssid"] == cur.get("ssid")
                      and n["channel"] == cur.get("channel")), None)
        if match:
            match["in_use"] = True
        else:
            nets.append(to_network(cur, in_use=True))
    return nets


def to_connection(cur: dict | None) -> dict | None:
    if not cur:
        return None
    n = to_network(cur, in_use=True)
    n.pop("security", None)
    n.pop("in_use", None)
    n["tx_rate_mbps"] = cur.get("tx_rate") or None
    n["interface"] = cur.get("interface")
    return n


# --- high-level API -------------------------------------------------------------------

def status() -> dict:
    data = call("status", timeout=30)
    return {"status": data.get("auth", "unknown"), "services_enabled": data.get("services_enabled")}


def request() -> dict:
    data = call("auth", timeout=120, background=False)
    return {"status": data.get("auth", "unknown"), "services_enabled": data.get("services_enabled")}


def scan() -> tuple[list[dict], str]:
    data = call("scan", timeout=60)
    if data.get("error") and not data.get("networks"):
        raise HelperUnavailable(data["error"])
    return networks_from_scan(data), data.get("auth", "unknown")


class MonitorStream:
    """Keeps one helper running in `monitor` mode and hands out its latest sample."""

    def __init__(self, interval: float) -> None:
        app = ensure_built()
        tmp = Path(tempfile.mkdtemp(prefix="subnetry-wifi-monitor-"))
        self.out = tmp / "samples.jsonl"
        self.stop_file = tmp / "stop"
        self._dir = tmp
        self._pos = 0
        self.latest: dict | None = None
        self.proc = subprocess.Popen(
            _open_args(app, "monitor", str(self.out), str(interval), str(self.stop_file), str(os.getpid())),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def read(self) -> dict | None:
        """Newest line written since the last read (or the previous one if nothing new)."""
        try:
            with open(self.out, encoding="utf-8") as f:
                f.seek(self._pos)
                chunk = f.read()
        except OSError:
            return self.latest
        complete = chunk[: chunk.rfind("\n") + 1]
        self._pos += len(complete.encode("utf-8"))
        for line in complete.splitlines():
            try:
                self.latest = json.loads(line)
            except json.JSONDecodeError:
                continue
        return self.latest

    def close(self) -> None:
        try:
            self.stop_file.write_text("stop")
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self._dir, ignore_errors=True)


async def wait_for_first(stream: MonitorStream, timeout: float = 15) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stream.read():
            return stream.latest
        await asyncio.sleep(0.2)
    return None
