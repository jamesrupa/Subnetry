"""Wi-Fi scanner: list nearby access points using the OS's own wireless tooling.

  Linux   -> nmcli (NetworkManager)
  Windows -> netsh wlan
  macOS   -> system_profiler SPAirPortDataType (SSIDs need Location Services on 14+)

Every parser returns the same normalized shape, so the UI and channel analysis
don't care which OS produced the data.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time

from ..system import IS_LINUX, IS_MAC, IS_WINDOWS, run_cmd
from . import macos

CHANNELS_24 = [1, 6, 11]  # the only non-overlapping 20 MHz channels in 2.4 GHz
# 5 GHz channels that need no radar detection (DFS), so every router supports them.
CHANNELS_5_NON_DFS = [36, 40, 44, 48, 149, 153, 157, 161, 165]
CHANNELS_5_DFS = range(52, 145)
# 6 GHz "preferred scanning channels": Wi-Fi 6E/7 devices look for networks here first.
CHANNELS_6_PSC = [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229]
CANDIDATES = {"2.4 GHz": CHANNELS_24, "5 GHz": CHANNELS_5_NON_DFS, "6 GHz": CHANNELS_6_PSC}
# Worth recommending a change only if the current channel is this much busier (≈ one strong neighbour).
CHANGE_THRESHOLD = 0.6


class WifiError(RuntimeError):
    pass


# --- unit helpers -----------------------------------------------------------------

def percent_to_dbm(pct: int) -> int:
    """Approximation used by Windows/NetworkManager: 0% ~ -100 dBm, 100% ~ -50 dBm."""
    return round(pct / 2 - 100)


def dbm_to_percent(dbm: int) -> int:
    return max(0, min(100, 2 * (dbm + 100)))


def band_for(channel: int | None, freq_mhz: int | None = None) -> str | None:
    if freq_mhz:
        if freq_mhz < 3000:
            return "2.4 GHz"
        if freq_mhz < 5925:
            return "5 GHz"
        return "6 GHz"
    if channel is None:
        return None
    return "2.4 GHz" if channel <= 14 else "5 GHz"


def channel_to_freq(channel: int, band: str | None) -> int | None:
    if band == "2.4 GHz":
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band == "5 GHz":
        return 5000 + 5 * channel
    if band == "6 GHz":
        return 5950 + 5 * channel
    return None


def make_network(
    ssid: str | None,
    bssid: str | None = None,
    *,
    signal_percent: int | None = None,
    signal_dbm: int | None = None,
    channel: int | None = None,
    freq_mhz: int | None = None,
    band: str | None = None,
    security: str | None = None,
    in_use: bool = False,
    **extra,
) -> dict:
    if signal_dbm is None and signal_percent is not None:
        signal_dbm = percent_to_dbm(signal_percent)
    if signal_percent is None and signal_dbm is not None:
        signal_percent = dbm_to_percent(signal_dbm)
    band = band or band_for(channel, freq_mhz)
    if freq_mhz is None and channel is not None:
        freq_mhz = channel_to_freq(channel, band)
    return {
        "ssid": ssid or "",
        "hidden": not ssid,
        "bssid": bssid.upper() if bssid else None,
        "signal_percent": signal_percent,
        "signal_dbm": signal_dbm,
        "channel": channel,
        "frequency_mhz": freq_mhz,
        "band": band,
        "security": security or "Open",
        "in_use": in_use,
        **extra,
    }


# --- Linux: nmcli -----------------------------------------------------------------

NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY"


def _split_nmcli(line: str) -> list[str]:
    """Split terse nmcli output on ':' while honouring '\\:' escapes."""
    parts = re.split(r"(?<!\\):", line)
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts]


def parse_nmcli(text: str) -> list[dict]:
    nets = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = _split_nmcli(line)
        if len(f) < 8:
            continue
        in_use, bssid, ssid, chan, freq, rate, signal, security = f[:8]
        freq_m = re.search(r"\d+", freq)
        nets.append(make_network(
            ssid,
            bssid or None,
            signal_percent=int(signal) if signal.isdigit() else None,
            channel=int(chan) if chan.isdigit() else None,
            freq_mhz=int(freq_m.group()) if freq_m else None,
            security=None if security.strip() in ("", "--") else security.strip(),
            in_use=in_use.strip() == "*",
            rate=rate or None,
        ))
    return nets


async def _scan_linux() -> list[dict]:
    res = await run_cmd(
        ["nmcli", "-t", "-f", NMCLI_FIELDS, "device", "wifi", "list", "--rescan", "yes"], timeout=30
    )
    if res is None:
        raise WifiError("`nmcli` (NetworkManager) is required for Wi-Fi scanning on Linux.")
    if not res.ok:
        raise WifiError(res.stderr.strip() or "nmcli failed to scan for Wi-Fi networks.")
    return parse_nmcli(res.stdout)


# --- Windows: netsh ---------------------------------------------------------------

def parse_netsh_networks(text: str, connected_bssid: str | None = None) -> list[dict]:
    nets: list[dict] = []
    ssid = auth = enc = None
    cur: dict | None = None

    def flush():
        if cur is not None:
            nets.append(make_network(
                ssid, cur.get("bssid"),
                signal_percent=cur.get("signal"),
                channel=cur.get("channel"),
                band=cur.get("band"),
                security=" / ".join(x for x in (auth, enc) if x and x != "None") or None,
                in_use=bool(connected_bssid and cur.get("bssid", "").upper() == connected_bssid.upper()),
                radio=cur.get("radio"),
            ))

    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key, value = key.strip(), value.strip()
        if re.match(r"^SSID \d+$", key):
            flush()
            cur = None
            ssid, auth, enc = value, None, None
        elif key == "Authentication":
            auth = value
        elif key == "Encryption":
            enc = value
        elif re.match(r"^BSSID \d+$", key):
            flush()
            cur = {"bssid": value}
        elif cur is not None:
            if key == "Signal":
                cur["signal"] = int(value.rstrip("%")) if value.rstrip("%").isdigit() else None
            elif key == "Channel" and value.isdigit():
                cur["channel"] = int(value)
            elif key == "Band":
                m = re.match(r"([\d.]+)\s*GHz", value)
                cur["band"] = f"{m.group(1)} GHz" if m else None
            elif key == "Radio type":
                cur["radio"] = value
    flush()
    return nets


def request_windows_scan(timeout: float = 6.0) -> bool:
    """Ask every Wi-Fi adapter to scan now, and wait until Windows says it's done.

    `netsh wlan show networks` only reports Windows' cached scan results, which are refreshed
    when something requests a scan (e.g. opening the Wi-Fi menu). Without this the list can be
    stale and hold little more than the network you're connected to. Uses the Native Wi-Fi API
    (WlanScan); no admin rights needed. Returns True if a scan was requested.
    """
    if sys.platform != "win32":
        return False
    import ctypes
    import threading
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
                    ("Data4", ctypes.c_ubyte * 8)]

    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256),
                    ("isState", ctypes.c_uint)]

    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD),
                    ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]

    class WLAN_NOTIFICATION_DATA(ctypes.Structure):
        _fields_ = [("NotificationSource", wintypes.DWORD), ("NotificationCode", wintypes.DWORD),
                    ("InterfaceGuid", GUID), ("dwDataSize", wintypes.DWORD), ("pData", ctypes.c_void_p)]

    SOURCE_NONE, SOURCE_ACM = 0, 0x08
    SCAN_COMPLETE, SCAN_FAIL = 7, 8
    try:
        wlan = ctypes.WinDLL("wlanapi.dll")
    except OSError:
        return False
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return False
    callback = None
    try:
        ifaces = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(ifaces)) != 0:
            return False
        try:
            count = ifaces.contents.dwNumberOfItems
            first = ctypes.addressof(ifaces.contents.InterfaceInfo)
            guids = [GUID.from_buffer_copy(WLAN_INTERFACE_INFO.from_address(first + i * ctypes.sizeof(WLAN_INTERFACE_INFO)).InterfaceGuid)
                     for i in range(count)]
        finally:
            wlan.WlanFreeMemory(ifaces)
        if not guids:
            return False

        pending = {bytes(g) for g in guids}
        done = threading.Event()
        lock = threading.Lock()
        NOTIFY = ctypes.WINFUNCTYPE(None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), ctypes.c_void_p)

        def on_notify(data, _context):
            d = data.contents
            if d.NotificationSource == SOURCE_ACM and d.NotificationCode in (SCAN_COMPLETE, SCAN_FAIL):
                with lock:
                    pending.discard(bytes(d.InterfaceGuid))
                    if not pending:
                        done.set()

        callback = NOTIFY(on_notify)  # keep a reference until we unregister
        registered = wlan.WlanRegisterNotification(handle, SOURCE_ACM, True, callback, None, None, None) == 0
        requested = False
        for g in guids:
            if wlan.WlanScan(handle, ctypes.byref(g), None, None, None) == 0:
                requested = True
            else:
                with lock:
                    pending.discard(bytes(g))
        if requested:
            if registered:
                done.wait(timeout)
            else:
                time.sleep(4)  # a scan usually takes 2-4 s
        return requested
    except Exception:
        return False
    finally:
        if callback is not None:
            try:
                wlan.WlanRegisterNotification(handle, SOURCE_NONE, True, None, None, None, None)
            except Exception:
                pass
        wlan.WlanCloseHandle(handle, None)


async def _scan_windows() -> list[dict]:
    await asyncio.to_thread(request_windows_scan)  # refresh Windows' cached list before reading it
    iface = await run_cmd(["netsh", "wlan", "show", "interfaces"])
    connected = None
    if iface:
        m = re.search(r"^\s*(?:AP )?BSSID\s*:\s*(\S+)", iface.stdout, re.M)
        connected = m.group(1) if m else None
    res = await run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20)
    if res is None:
        raise WifiError("Could not run `netsh`.")
    nets = parse_netsh_networks(res.stdout, connected)
    if not nets and (not res.ok or "location" in res.stdout.lower()):
        raise WifiError(
            (res.stdout.strip() or res.stderr.strip() or "netsh returned no networks.")
            + "\n\nOn Windows 11, Wi-Fi scanning needs Location access: Settings > Privacy & security > Location."
        )
    return nets


# --- macOS: system_profiler -------------------------------------------------------

def _mac_security(raw: str | None) -> str | None:
    if not raw:
        return None
    s = raw.replace("spairport_security_mode_", "").replace("_", " ").strip()
    return "Open" if s == "none" else s.upper().replace("PERSONAL", "Personal").replace("ENTERPRISE", "Enterprise")


def _mac_network(entry: dict, in_use: bool) -> dict:
    chan_raw = str(entry.get("spairport_network_channel", ""))
    chan_m = re.match(r"(\d+)", chan_raw)
    band = None
    if "6GHz" in chan_raw:
        band = "6 GHz"
    elif "5GHz" in chan_raw:
        band = "5 GHz"
    elif "2GHz" in chan_raw:
        band = "2.4 GHz"
    sig_m = re.search(r"(-?\d+)\s*dBm", str(entry.get("spairport_signal_noise", "")))
    noise_m = re.search(r"/\s*(-?\d+)\s*dBm", str(entry.get("spairport_signal_noise", "")))
    redacted = macos.is_redacted(entry.get("_name"))  # macOS 14+ without Location permission
    return make_network(
        None if redacted else entry.get("_name"),
        None,
        signal_dbm=int(sig_m.group(1)) if sig_m else None,
        channel=int(chan_m.group(1)) if chan_m else None,
        band=band,
        security=_mac_security(entry.get("spairport_security_mode")),
        in_use=in_use,
        noise_dbm=int(noise_m.group(1)) if noise_m else None,
        radio=entry.get("spairport_network_phymode"),
        redacted=redacted,
    )


def parse_system_profiler(data: dict) -> list[dict]:
    nets = []
    for section in data.get("SPAirPortDataType", []):
        for iface in section.get("spairport_airport_interfaces", []):
            current = iface.get("spairport_current_network_information")
            if current:
                nets.append(_mac_network(current, True))
            for entry in iface.get("spairport_airport_other_local_wireless_networks", []):
                nets.append(_mac_network(entry, False))
    return nets


async def _scan_mac() -> list[dict]:
    # 1. The Subnetry Wi-Fi Helper app: the only reliable way to keep Location permission (and so see names).
    from . import macos_helper
    try:
        nets, _auth = await asyncio.to_thread(macos_helper.scan)
        if nets:
            return nets
    except macos_helper.HelperUnavailable:
        pass
    # 2. CoreWLAN from Python directly, 3. system_profiler.
    try:
        nets = await asyncio.to_thread(macos.scan_corewlan)
        if nets:
            return nets
    except Exception:  # pyobjc missing or the scan failed: fall back to system_profiler
        pass
    return await _scan_system_profiler()


async def _scan_system_profiler() -> list[dict]:
    res = await run_cmd(["system_profiler", "SPAirPortDataType", "-json"], timeout=40)
    if res is None or not res.ok:
        raise WifiError("system_profiler failed to report Wi-Fi networks.")
    try:
        return parse_system_profiler(json.loads(res.stdout))
    except json.JSONDecodeError as exc:
        raise WifiError(f"Could not parse system_profiler output: {exc}") from exc


# --- analysis ---------------------------------------------------------------------

def _overlap_24(a: int, b: int) -> float:
    """How much two 20 MHz 2.4 GHz channels interfere (1.0 = same, 0 = >=5 apart)."""
    return max(0.0, 1 - abs(a - b) / 5)


_BLOCKS_5 = [36, 52, 100, 116, 132, 149]  # 80 MHz channel groups in 5 GHz


def _block(band: str, ch: int) -> int | None:
    """Which 80 MHz block a 5/6 GHz channel belongs to (wide channels on the same block overlap)."""
    if band == "5 GHz":
        return next((b for b in reversed(_BLOCKS_5) if b <= ch <= b + 16), None)
    if band == "6 GHz":
        return (ch - 1) // 16
    return None


def interference(band: str, a: int, b: int) -> float:
    if band == "2.4 GHz":
        return _overlap_24(a, b)
    if a == b:
        return 1.0
    block = _block(band, a)
    return 0.5 if block is not None and block == _block(band, b) else 0.0


def channel_scores(band: str, nets: list[dict], channels, own_ssid: str | None = None) -> dict[int, float]:
    """Congestion per channel: overlapping neighbours weighted by how strongly we hear them.

    Networks with the same name as yours (your own access points / mesh nodes) don't count.
    """
    neighbours = [n for n in nets if n.get("band") == band and n.get("channel")
                  and not (own_ssid and n.get("ssid") == own_ssid)]
    return {ch: round(sum(interference(band, ch, n["channel"]) * (n.get("signal_percent") or 50) / 100
                          for n in neighbours), 2) for ch in channels}


def recommend_channel(band: str, nets: list[dict], current: int | None = None, own_ssid: str | None = None) -> dict:
    candidates = list(CANDIDATES.get(band, []))
    scores = channel_scores(band, nets, candidates, own_ssid)
    best = min(candidates, key=lambda c: (scores[c], candidates.index(c))) if candidates else None
    result = {"band": band, "channel": best, "score": scores.get(best), "scores": scores,
              "networks": sum(1 for n in nets if n.get("band") == band and not (own_ssid and n.get("ssid") == own_ssid))}
    if current:
        cur_score = channel_scores(band, nets, [current], own_ssid)[current]
        overlapping = [n for n in nets if n.get("band") == band and n.get("channel")
                       and not (own_ssid and n.get("ssid") == own_ssid) and interference(band, current, n["channel"]) > 0]
        off_grid = band == "2.4 GHz" and current not in CHANNELS_24
        result.update(
            current=current,
            current_score=cur_score,
            overlapping=len(overlapping),
            off_grid=off_grid,
            dfs=band == "5 GHz" and current in CHANNELS_5_DFS,
            change=best is not None and best != current
                   and (off_grid or cur_score - (scores[best] or 0) >= CHANGE_THRESHOLD),
        )
    return result


def channel_report(nets: list[dict]) -> dict:
    """Per-band channel usage, the least-congested channel per band, and advice for your own network."""
    usage: dict[str, dict[int, int]] = {}
    for n in nets:
        if n["band"] and n["channel"]:
            usage.setdefault(n["band"], {})
            usage[n["band"]][n["channel"]] = usage[n["band"]].get(n["channel"], 0) + 1

    connected = next((n for n in nets if n.get("in_use")), None)
    own = connected["ssid"] if connected and connected.get("ssid") else None
    recommendations = {band: recommend_channel(band, nets, own_ssid=own) for band in CANDIDATES if band in usage}
    report = {
        "usage": {band: dict(sorted(ch.items())) for band, ch in usage.items()},
        "recommendations": recommendations,
    }
    if connected and connected.get("band") in CANDIDATES and connected.get("channel"):
        report["connected"] = recommend_channel(connected["band"], nets, connected["channel"], own)
    return report


async def scan_wifi() -> dict:
    if IS_LINUX:
        nets = await _scan_linux()
    elif IS_WINDOWS:
        nets = await _scan_windows()
    elif IS_MAC:
        nets = await _scan_mac()
    else:
        raise WifiError("Wi-Fi scanning is not supported on this operating system yet.")
    nets.sort(key=lambda n: (not n["in_use"], -(n["signal_percent"] or 0)))
    result = {"networks": nets, "channels": channel_report(nets)}
    if IS_MAC and any(n.get("redacted") for n in nets):
        # Names are hidden: tell the UI so it can explain and offer to request Location access.
        result["location"] = await asyncio.to_thread(macos.location_status)
    return result
