"""DNSDumpster: passive DNS reconnaissance (subdomains/hosts, their IPs, ASN, country) via its official API.

    GET https://api.dnsdumpster.com/domain/<domain>    header  X-API-Key: <key>

A free API key comes with a (free) dnsdumpster.com account. The API allows one request every
2 seconds, so calls are spaced out here, and results are cached for a few minutes so looking
at the same domain again doesn't spend quota. The key is stored in Subnetry's settings file
in the reports folder (or set DNSDUMPSTER_API_KEY), never in the project folder.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import time
from collections import Counter
from pathlib import Path

import httpx

from . import dnsinfo
from .report import reports_dir

API_URL = "https://api.dnsdumpster.com/domain/{domain}"
SIGNUP_URL = "https://dnsdumpster.com/"
ENV_KEY = "DNSDUMPSTER_API_KEY"
MIN_INTERVAL = 2.0  # seconds between requests (the API's limit)
CACHE_SECONDS = 600
RECORD_TYPES = ("a", "aaaa", "cname", "mx", "ns")
# Host names that are often worth a second look when they're publicly visible.
NOTABLE = re.compile(r"(?:^|[.-])(dev|develop|test|testing|staging|stage|stg|uat|qa|beta|old|legacy|backup|bak|admin|"
                     r"internal|intranet|vpn|remote|rdp|jenkins|gitlab|git|jira|ftp|db|sql|phpmyadmin|cpanel|webmail)\d*(?:[.-]|$)")


class DumpsterError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


# --- API key --------------------------------------------------------------------------

def settings_path() -> Path:
    return reports_dir() / ".subnetry-settings.json"


def _read_settings() -> dict:
    try:
        return json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def api_key() -> tuple[str | None, str | None]:
    """(key, where it came from: "env" or "settings")."""
    if os.environ.get(ENV_KEY, "").strip():
        return os.environ[ENV_KEY].strip(), "env"
    key = (_read_settings().get("dnsdumpster_api_key") or "").strip()
    return (key, "settings") if key else (None, None)


def save_key(key: str | None) -> None:
    """Store the key (or remove it when empty). Readable only by you where the OS supports it."""
    data = _read_settings()
    key = (key or "").strip()
    if key:
        data["dnsdumpster_api_key"] = key
    else:
        data.pop("dnsdumpster_api_key", None)
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    _cache.clear()


def status() -> dict:
    key, source = api_key()
    return {"configured": bool(key), "source": source, "hint": f"…{key[-4:]}" if key and len(key) > 8 else None,
            "signup_url": SIGNUP_URL}


# --- request ---------------------------------------------------------------------------

_lock = asyncio.Lock()
_last_call = 0.0
_cache: dict[str, tuple[float, dict]] = {}


def _ip(entry: dict) -> dict:
    out = {k: entry.get(k) for k in ("ip", "asn", "asn_name", "asn_range", "country", "country_code", "ptr")}
    banners = entry.get("banners")
    if isinstance(banners, dict) and banners:  # web server / TLS details, when DNSDumpster has them
        out["banners"] = {
            proto: ({k: v for k, v in info.items() if isinstance(v, (str, int, float))} if isinstance(info, dict) else str(info))
            for proto, info in banners.items()
        }
    return out


def normalize(domain: str, data: dict) -> dict:
    """The API's JSON as one host list (with record type) plus summaries for the UI."""
    hosts = []
    for rtype in RECORD_TYPES:
        for rec in data.get(rtype) or []:
            if not isinstance(rec, dict):
                continue
            host, priority = str(rec.get("host") or "").strip().rstrip("."), None
            if rtype == "mx" and " " in host:  # MX hosts come as "10 mail.example.com"
                first, _, rest = host.partition(" ")
                if first.isdigit():
                    priority, host = int(first), rest.strip().rstrip(".")
            hosts.append({"type": rtype.upper(), "host": host, "priority": priority,
                          "ips": [_ip(i) for i in rec.get("ips") or [] if isinstance(i, dict)]})
    ips = [ip for h in hosts for ip in h["ips"] if ip.get("ip")]
    unique_ips = {ip["ip"]: ip for ip in ips}
    asns = Counter(f"{ip.get('asn_name') or 'Unknown'}" + (f" (AS{ip['asn']})" if ip.get("asn") else "") for ip in unique_ips.values())
    countries = Counter(ip.get("country") or "Unknown" for ip in unique_ips.values())
    shown_a = len(data.get("a") or [])
    total_a = data.get("total_a_recs")
    names = dict.fromkeys(h["host"].lower() for h in hosts if h["type"] in ("A", "AAAA", "CNAME") and h["host"])
    notable = [n for n in names if NOTABLE.search(n.removesuffix("." + domain))]
    return {
        "domain": domain,
        "hosts": hosts,
        "notable": notable,
        "txt": [t for t in data.get("txt") or [] if isinstance(t, str)],
        "counts": {t.upper(): len(data.get(t) or []) for t in RECORD_TYPES} | {"TXT": len(data.get("txt") or [])},
        "total_a": total_a if isinstance(total_a, int) else None,
        "shown_a": shown_a,
        "more_available": isinstance(total_a, int) and total_a > shown_a,
        "unique_ips": len(unique_ips),
        "asns": asns.most_common(8),
        "countries": countries.most_common(8),
        "fetched_at": time.strftime("%Y-%m-%d %H:%M"),
    }


async def lookup(query: str, transport: httpx.AsyncBaseTransport | None = None) -> dict:
    key, _ = api_key()
    if not key:
        raise DumpsterError("Add your DNSDumpster API key first (free with a dnsdumpster.com account).", 400)
    try:
        domain = dnsinfo.clean_name(query)
    except dnsinfo.DnsError as exc:
        raise DumpsterError(str(exc), 400) from exc
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise DumpsterError("DNSDumpster looks up domain names, not IP addresses.", 400)

    cached = _cache.get(domain)
    if cached and time.time() - cached[0] < CACHE_SECONDS:
        return {**cached[1], "cached": True}

    global _last_call
    async with _lock:  # one request every 2 seconds, as the API requires
        wait = MIN_INTERVAL - (time.monotonic() - _last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            async with httpx.AsyncClient(timeout=45, transport=transport,
                                         headers={"X-API-Key": key, "User-Agent": "Subnetry"}) as client:
                r = await client.get(API_URL.format(domain=domain))
        except httpx.HTTPError as exc:
            raise DumpsterError(f"Couldn't reach DNSDumpster: {exc}") from exc
        finally:
            _last_call = time.monotonic()

    if r.status_code in (401, 403):
        raise DumpsterError("DNSDumpster rejected the API key. Check it on your dnsdumpster.com account page.", 401)
    if r.status_code == 429:
        raise DumpsterError("DNSDumpster's rate limit was reached (one request every 2 seconds, plus a daily quota "
                            "on free accounts). Try again in a little while.", 429)
    try:
        data = r.json()
    except ValueError as exc:
        raise DumpsterError(f"DNSDumpster returned an unexpected response (HTTP {r.status_code}).") from exc
    if r.status_code >= 400 or (isinstance(data, dict) and data.get("error")):
        message = data.get("error") if isinstance(data, dict) else None
        raise DumpsterError(f"DNSDumpster: {message or f'HTTP {r.status_code}'}", 400 if r.status_code < 500 else 502)
    if not isinstance(data, dict):
        raise DumpsterError("DNSDumpster returned an unexpected response.")
    result = normalize(domain, data)
    _cache[domain] = (time.time(), result)
    return {**result, "cached": False}
