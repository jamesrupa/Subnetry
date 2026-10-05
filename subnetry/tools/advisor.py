"""Turn scan results into prioritized, plain-language recommendations.

Every rule is a small function that looks at one part of the report and returns
recommendations. Each recommendation says what was found, why it matters and
what to change, so the report doubles as a learning aid.
"""

from __future__ import annotations


SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "good": 3}
PENALTY = {"critical": 25, "warning": 10, "info": 0, "good": 0}


def rec(severity: str, category: str, title: str, detail: str, action: str = "") -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail, "action": action}


# --- speed ------------------------------------------------------------------------

OOKLA_INSTALL = {
    "Darwin": "`brew tap teamookla/speedtest`, `brew trust teamookla/speedtest`, then `brew install speedtest --force`",
    "Windows": "`winget install Ookla.Speedtest.CLI` in PowerShell",
    "Linux": "the instructions at speedtest.net/apps/cli",
}


def engine_notes(speed: dict) -> list[dict]:
    """Say when the result came from Cloudflare instead of Speedtest.net, and why."""
    if speed.get("engine_id") != "cloudflare":
        return []
    if speed.get("fallback_reason"):
        return [rec("info", "Speed", "Measured with Cloudflare (Speedtest.net didn't finish)",
                    f"Speedtest.net failed ({speed['fallback_reason']}), so Cloudflare's test was used instead. "
                    "Results are comparable but can differ by a few percent.",
                    "Run the Speed Test tab again later to get a Speedtest.net result.")]
    if speed.get("ookla_installed") is False:
        import platform

        how = OOKLA_INSTALL.get(platform.system(), OOKLA_INSTALL["Linux"])
        return [rec("info", "Speed", "Measured with Cloudflare (Speedtest.net CLI not installed)",
                    "Subnetry prefers Speedtest.net (Ookla), the test most ISPs quote, but its command-line tool "
                    "isn't installed, so Cloudflare's test was used.",
                    f"Install the Speedtest.net CLI with {how}, then restart Subnetry.")]
    return []

def speed_rules(speed: dict | None) -> list[dict]:
    if not speed:
        return []
    if speed.get("error"):
        return [rec(
            "critical", "Speed", "Speed test could not complete",
            f"The test servers could not be reached ({speed['error']}).",
            "Check that you are online: open a website, restart the router/modem, and make sure no "
            "firewall or VPN is blocking the speed test servers.",
        )]
    out = engine_notes(speed)
    down, up = speed.get("download_mbps"), speed.get("upload_mbps")
    lat, jit = speed.get("latency_ms"), speed.get("jitter_ms")

    if down is not None:
        if down < 10:
            out.append(rec("critical", "Speed", f"Very slow download ({down:.1f} Mbps)",
                           "Under 10 Mbps struggles with HD streaming and large downloads, especially with several devices.",
                           "Re-run the test with a wired connection. If it's still slow, restart the modem and contact your ISP "
                           "with these results; otherwise the problem is your Wi-Fi (see the Wi-Fi items)."))
        elif down < 25:
            out.append(rec("warning", "Speed", f"Slow download ({down:.1f} Mbps)",
                           "25 Mbps is the usual minimum for a household's streaming and video calls.",
                           "Compare with your plan's advertised speed. Test once wired to tell an ISP problem from a Wi-Fi problem."))
        elif down >= 100:
            out.append(rec("good", "Speed", f"Fast download ({down:.0f} Mbps)",
                           "Plenty for 4K streaming and several heavy users at once."))
        else:
            out.append(rec("good", "Speed", f"Good download ({down:.0f} Mbps)",
                           "Enough for HD streaming and video calls on a few devices at once."))
    if up is not None:
        if up < 3:
            out.append(rec("warning", "Speed", f"Slow upload ({up:.1f} Mbps)",
                           "Uploads under 3 Mbps make video calls, cloud backups and sending large files painful.",
                           "Check whether your plan includes a faster upload tier; cable plans are often asymmetric."))
        elif up < 10:
            out.append(rec("info", "Speed", f"Modest upload ({up:.1f} Mbps)",
                           "Fine for calls, but cloud backups and large uploads will be slow."))
    if lat is not None:
        if lat > 100:
            out.append(rec("critical", "Speed", f"High latency ({lat:.0f} ms)",
                           "Over 100 ms makes calls, gaming and even page loads feel sluggish.",
                           "Test wired to rule out Wi-Fi. Pause big downloads/backups during the test; if it persists, "
                           "ask your ISP about line quality."))
        elif lat > 50:
            out.append(rec("warning", "Speed", f"Elevated latency ({lat:.0f} ms)",
                           "Typical broadband is 10-40 ms. Higher values hurt gaming and real-time calls.",
                           "Move closer to the router or use Ethernet, and check for other devices saturating the connection."))
    loss = speed.get("packet_loss")
    if loss is not None:
        if loss >= 2:
            out.append(rec("critical" if loss >= 5 else "warning", "Speed", f"Packet loss ({loss:.1f}%)",
                           "Lost packets have to be resent. Even 1-2% makes calls choppy and games lag, and slows downloads.",
                           "Test over Ethernet: if the loss disappears, it's Wi-Fi interference or weak signal. If it stays, "
                           "check the modem's cables and signal levels and contact your ISP with this result."))
        elif loss > 0.5:
            out.append(rec("info", "Speed", f"Minor packet loss ({loss:.1f}%)",
                           "A little loss during a busy test is common; worth re-testing if calls ever stutter."))
    if jit is not None:
        if jit > 30:
            out.append(rec("warning", "Speed", f"High jitter ({jit:.0f} ms)",
                           "Jitter is how much latency varies. Over 30 ms causes choppy voice/video calls.",
                           "Usually caused by Wi-Fi interference or a congested link. Try 5 GHz or Ethernet, "
                           "and enable QoS / Smart Queue (SQM) on the router if it has it."))
        elif jit > 15:
            out.append(rec("info", "Speed", f"Some jitter ({jit:.0f} ms)",
                           "Noticeable on calls under load; not a problem for browsing or streaming."))
    return out


# --- Wi-Fi ------------------------------------------------------------------------

def classify_security(security: str | None) -> str:
    s = (security or "").upper()
    if not s or s == "OPEN" or s == "NONE":
        return "open"
    if "WEP" in s:
        return "wep"
    if "WPA3" in s or "SAE" in s or "OWE" in s:
        return "wpa3"
    if "WPA2" in s or "CCMP" in s or "AES" in s:
        return "wpa2-tkip" if "TKIP" in s and "CCMP" not in s and "AES" not in s else "wpa2"
    return "wpa"


def wifi_rules(wifi: dict | None) -> list[dict]:
    if wifi is None:
        return []
    if wifi.get("error"):
        return [rec("info", "Wi-Fi", "Wi-Fi analysis unavailable", wifi["error"],
                    "If this computer uses Ethernet, run the full scan from a laptop on Wi-Fi to analyse the wireless network.")]
    nets = wifi.get("networks", [])
    cur = next((n for n in nets if n.get("in_use")), None)
    out = []
    if cur is None:
        out.append(rec("info", "Wi-Fi", "Not connected to Wi-Fi",
                       f"{len(nets)} nearby networks were found, but this computer isn't connected over Wi-Fi, "
                       "so signal and channel checks for your own network were skipped."))
        return out

    name = cur["ssid"] or "your network"
    dbm, band, ch = cur.get("signal_dbm"), cur.get("band"), cur.get("channel")

    # Signal strength
    if dbm is not None:
        fixes = ("Move the router to a central, raised spot away from walls, metal and microwaves; "
                 "or add a mesh node/access point near where you use this device, or use Ethernet.")
        if dbm < -75:
            out.append(rec("critical", "Wi-Fi", f"Very weak signal to {name} ({dbm} dBm)",
                           "Below -75 dBm, connections drop and speeds fall sharply.", fixes))
        elif dbm < -67:
            out.append(rec("warning", "Wi-Fi", f"Weak signal to {name} ({dbm} dBm)",
                           "-67 dBm is the usual minimum for reliable video calls and streaming.", fixes))
        elif dbm < -60:
            out.append(rec("info", "Wi-Fi", f"Fair signal to {name} ({dbm} dBm)",
                           "Fine for browsing; borderline for calls in the far corners."))
        else:
            out.append(rec("good", "Wi-Fi", f"Strong signal to {name} ({dbm} dBm)",
                           "Signal strength isn't limiting your speed."))

    # Security
    sec = classify_security(cur.get("security"))
    if sec in ("open", "wep"):
        out.append(rec("critical", "Security", f"{name} is {'not encrypted' if sec == 'open' else 'using broken WEP encryption'}",
                       "Anyone nearby can join the network and read unencrypted traffic.",
                       "In the router's wireless settings set security to WPA2-Personal (AES) or WPA3 and choose a long passphrase."))
    elif sec in ("wpa", "wpa2-tkip"):
        out.append(rec("warning", "Security", f"{name} uses outdated WPA/TKIP encryption",
                       "WPA (v1) and TKIP are deprecated and can force the whole network down to slow 802.11g speeds.",
                       "Switch the router to WPA2 (AES/CCMP) or WPA3."))
    elif sec == "wpa2":
        out.append(rec("info", "Security", f"{name} uses WPA2",
                       "WPA2 with AES is still secure. WPA3 adds protection against password-guessing attacks.",
                       "If all your devices support it, choose \"WPA2/WPA3 mixed\" or WPA3 in the router settings."))
    else:
        out.append(rec("good", "Security", f"{name} uses WPA3", "The current, strongest Wi-Fi security standard."))

    # Band
    same_ssid = [n for n in nets if n["ssid"] and n["ssid"] == cur["ssid"]]
    if band == "2.4 GHz":
        if any(n.get("band") in ("5 GHz", "6 GHz") for n in same_ssid):
            out.append(rec("warning", "Wi-Fi", "Connected on 2.4 GHz although 5 GHz is available",
                           "Your router also broadcasts this network on 5 GHz, which is usually several times faster "
                           "and far less crowded. 2.4 GHz only wins at long range.",
                           "Move closer to the router so the device switches over, or enable band steering on the router."))
        elif any(n["ssid"] and n["ssid"] != cur["ssid"] and n["ssid"].startswith(cur["ssid"]) and n.get("band") == "5 GHz" for n in nets):
            out.append(rec("warning", "Wi-Fi", "Connected on 2.4 GHz; a separate 5 GHz network exists",
                           "A similarly named 5 GHz network (e.g. \"-5G\") is nearby, which is usually much faster.",
                           "Connect this device to the 5 GHz network when you are within range of the router."))

    # Channel choice: should you change the channel your own network uses?
    out += channel_rules(cur, nets)

    crowded_24 = [n for n in nets if n.get("band") == "2.4 GHz"]
    if len(crowded_24) > 15:
        out.append(rec("info", "Wi-Fi", f"Busy 2.4 GHz environment ({len(crowded_24)} networks)",
                       "Apartment-style congestion; no 2.4 GHz channel will be clean.",
                       "Use 5 GHz (or 6 GHz with Wi-Fi 6E) for anything that needs speed."))
    return out


def channel_rules(cur: dict, nets: list[dict]) -> list[dict]:
    """Recommend keeping or changing the connected network's channel, with the exact setting to use."""
    from .wifiscan import recommend_channel

    band, ch = cur.get("band"), cur.get("channel")
    if band not in ("2.4 GHz", "5 GHz", "6 GHz") or not ch:
        return []
    r = recommend_channel(band, nets, ch, cur.get("ssid") or None)
    best, n_over = r["channel"], r["overlapping"]
    neighbours = f"{n_over} neighbouring network{'s' if n_over != 1 else ''}"
    how = (f"In your router's wireless settings, set the {band} channel to {best} instead of {ch}"
           f"{' (or Auto)' if band != '6 GHz' else ''}. On a mesh system, change it in the mesh app; "
           "devices reconnect automatically within a minute.")
    out = []
    if r["off_grid"]:
        out.append(rec("warning", "Wi-Fi", f"Change Wi-Fi channel: {ch} → {best} (2.4 GHz)",
                       f"Channel {ch} overlaps two of the standard channels (1, 6 and 11), so it picks up interference "
                       f"from both sides. {neighbours.capitalize()} overlap it right now.", how))
    elif r["change"]:
        extra = {
            "2.4 GHz": "Only channels 1, 6 and 11 don't overlap; {best} has the least traffic around you.",
            "5 GHz": "{best} needs no radar checks (non-DFS) and has the least overlap with nearby networks.",
            "6 GHz": "{best} is a preferred scanning channel (PSC), so devices find it quickly, and it's the quietest nearby.",
        }[band].format(best=best)
        out.append(rec("warning", "Wi-Fi", f"Change Wi-Fi channel: {ch} → {best} ({band})",
                       f"Your network shares channel {ch} with {neighbours}, so they take turns using the airwaves. "
                       + extra, how))
    else:
        detail = (f"No nearby networks overlap channel {ch}." if n_over == 0 else
                  f"{neighbours.capitalize()} overlap it, but no other {band} channel is meaningfully quieter.")
        out.append(rec("good", "Wi-Fi", f"Channel {ch} is a good choice ({band})", detail + " No change needed."))
    if r.get("dfs") and not r["change"]:
        out.append(rec("info", "Wi-Fi", f"Channel {ch} is a DFS (radar-shared) channel",
                       "DFS channels are often quiet, but the router must leave them briefly if it detects radar, "
                       "which drops Wi-Fi for about a minute.",
                       f"If you notice short, random Wi-Fi dropouts, switch to {best}, which doesn't need radar checks."))
    if band != "6 GHz" and any(n.get("band") == "6 GHz" and n.get("ssid") == cur.get("ssid") for n in nets):
        out.append(rec("info", "Wi-Fi", "Your router also offers 6 GHz",
                       "6 GHz (Wi-Fi 6E/7) has far more space and almost no interference, but shorter range.",
                       "Devices that support it will use it when close to the router; no change needed."))
    return out


# --- devices & ports ------------------------------------------------------------------

RISKY_PORTS = {
    23: ("critical", "Telnet", "sends passwords and everything else unencrypted",
         "Disable Telnet on the device (use SSH instead) or remove the device if it can't be secured."),
    21: ("warning", "FTP", "sends logins unencrypted",
         "Disable FTP or replace it with SFTP/FTPS."),
    3389: ("warning", "Remote Desktop (RDP)", "is a frequent target of password-guessing and exploits",
           "Disable it if unused; never forward port 3389 on the router. Use a VPN for remote access."),
    5900: ("warning", "VNC", "often has weak or no authentication",
           "Disable VNC if unused, set a strong password, and never forward it to the internet."),
    6379: ("warning", "Redis", "often runs without authentication",
           "Bind it to localhost or require a password."),
    27017: ("warning", "MongoDB", "often runs without authentication",
            "Bind it to localhost or enable authentication."),
    1883: ("info", "MQTT", "is an unencrypted IoT messaging protocol",
           "Fine on a trusted LAN; enable a username/password on the broker."),
}


def network_rules(network: dict | None, system: dict | None) -> list[dict]:
    if network is None:
        return []
    out = []
    if network.get("error"):
        return [rec("info", "Network", "Device scan unavailable", network["error"])]
    hosts = network.get("hosts", [])
    gw = network.get("gateway") or (system or {}).get("gateway")
    if not gw:
        out.append(rec("warning", "Network", "No default gateway",
                       "This computer has no route to other networks, so it can't reach the internet.",
                       "Reconnect to the network, or check the IP settings are set to DHCP/automatic."))

    randomized = sum(1 for h in hosts if h.get("mac_randomized"))
    unnamed = sum(1 for h in hosts if not h.get("hostname") and not h.get("is_self") and not h.get("is_gateway"))
    detail = f"{len(hosts)} devices responded on {network.get('network')}."
    if randomized:
        detail += (f" {randomized} {'uses a' if randomized == 1 else 'use'} private (randomized) MAC "
                   f"address{'' if randomized == 1 else 'es'}, which is normal for modern phones and laptops.")
    out.append(rec("info", "Network", f"{len(hosts)} devices on your network", detail,
                   f"Review the device list for anything you don't recognise ({unnamed} have no name). Unknown "
                   "devices can be blocked in the router, and changing the Wi-Fi password removes everyone." if hosts else ""))

    out += port_rules(hosts)
    router = next((h for h in hosts if h.get("is_gateway")), None)
    if router:
        out += router_rules(router)
    return out


def _risky_port(port: int) -> tuple[str, str, str, str] | None:
    """(severity, name, why, action) for a port worth flagging, or None."""
    if port in RISKY_PORTS:
        return RISKY_PORTS[port]
    from .portref import describe

    entry = next((p for p in describe(port) if p["protocol"] == "TCP" and p["risk"] == "risky"), None)
    if entry is None:
        return None
    why = entry["description"].rstrip(".")
    return ("warning", entry["name"], f"is reachable. {why}" if why else "is reachable",
            (entry["note"] + " " if entry["note"] else "") + "Disable the service if it isn't needed, and never forward this port on the router.")


def port_rules(hosts: list[dict]) -> list[dict]:
    """Risky services, grouped per port so one recommendation lists every affected device."""
    by_port: dict[int, list[str]] = {}
    scanned = [h for h in hosts if h.get("ports") is not None]
    for h in scanned:
        for p in h["ports"].get("open", []):
            if _risky_port(p["port"]):
                by_port.setdefault(p["port"], []).append(h["ip"])
    out = []
    for port, ips in sorted(by_port.items(), key=lambda kv: SEVERITY_ORDER[_risky_port(kv[0])[0]]):
        sev, name, why, action = _risky_port(port)
        out.append(rec(sev, "Security", f"{name} (port {port}) open on {len(ips)} device{'s' if len(ips) > 1 else ''}",
                       f"{', '.join(ips)}: {name} {why}.", action))
    if scanned and not by_port:
        count = max((h["ports"].get("scanned", 0) for h in scanned), default=0)
        out.append(rec("good", "Security", "No risky services found",
                       f"Checked {count or 'the common'} ports on {len(scanned)} device{'s' if len(scanned) > 1 else ''}: "
                       "nothing like Telnet, FTP, Remote Desktop, VNC or open databases is reachable."))
    return out


def router_rules(router: dict) -> list[dict]:
    if router.get("ports") is None:
        return []
    out = []
    ports = {p["port"] for p in router["ports"].get("open", [])}
    if 80 in ports and 443 not in ports:
        out.append(rec("warning", "Security", "Router admin page uses plain HTTP",
                       f"The router ({router['ip']}) serves its admin page without encryption, so the admin password "
                       "crosses the network in clear text.",
                       "Enable HTTPS for the admin interface if the router supports it, and use a strong admin password "
                       "(not the default printed on the label)."))
    if ports & {5000, 49152}:
        out.append(rec("info", "Security", "UPnP appears to be enabled on the router",
                       "UPnP lets devices open ports on your router automatically. It's convenient for gaming and video "
                       "calls but malware can use it too.",
                       "If you don't need it (no consoles or P2P apps), disable UPnP in the router settings."))
    if ports & {22, 23}:
        out.append(rec("info", "Security", "Router allows SSH/Telnet logins",
                       "Remote shell access to the router is enabled on the LAN.",
                       "Turn it off unless you use it, and make sure remote management from the internet (WAN) is disabled."))
    return out


# --- overall ----------------------------------------------------------------------

def recommend(report: dict) -> list[dict]:
    recs = (
        speed_rules(report.get("speed"))
        + wifi_rules(report.get("wifi"))
        + network_rules(report.get("network"), report.get("system"))
    )
    return sorted(recs, key=lambda r: SEVERITY_ORDER[r["severity"]])


def _score_value(recs: list[dict]) -> int:
    value = max(0, 100 - sum(PENALTY[r["severity"]] for r in recs))
    if any(r["severity"] == "critical" for r in recs):
        value = min(value, 74)  # a critical problem never grades better than "Fair"
    return value


def grade_for(value: int) -> str:
    return "Excellent" if value >= 90 else "Good" if value >= 75 else "Fair" if value >= 50 else "Poor"


def improvements(recs: list[dict], limit: int = 5) -> list[dict]:
    """The fixes that would raise the score most, with how many points each is worth."""
    current = _score_value(recs)
    out = []
    for i, r in enumerate(recs):
        if not PENALTY[r["severity"]]:
            continue
        gain = _score_value(recs[:i] + recs[i + 1:]) - current
        out.append({"title": r["title"], "action": r["action"] or r["detail"], "severity": r["severity"],
                    "category": r["category"], "points": gain})
    out.sort(key=lambda x: (-x["points"], SEVERITY_ORDER[x["severity"]]))
    return out[:limit]


def score(recs: list[dict]) -> dict:
    value = _score_value(recs)
    counts = {s: sum(1 for r in recs if r["severity"] == s) for s in SEVERITY_ORDER}
    return {"value": value, "grade": grade_for(value), "counts": counts, "improvements": improvements(recs)}
