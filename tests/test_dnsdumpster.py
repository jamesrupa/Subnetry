"""DNSDumpster integration, against a fake API built from the documented response format."""

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from subnetry.server import app
from subnetry.tools import dnsdumpster

KEY = "0123456789abcdef0123456789abcdef"

SAMPLE = {
    "a": [
        {"host": "example.com", "ips": [{"ip": "93.184.215.14", "asn": "15133", "asn_name": "EDGECAST", "asn_range": "93.184.215.0/24",
                                          "country": "United States", "country_code": "US", "ptr": ""}]},
        {"host": "dev.example.com", "ips": [{"ip": "203.0.113.7", "asn": "64500", "asn_name": "EXAMPLE-HOSTING",
                                              "country": "Germany", "country_code": "DE", "ptr": "srv7.hosting.example",
                                              "banners": {"https": {"server": "nginx", "title": "Dev portal", "cn": "dev.example.com"}}}]},
        {"host": "vpn.example.com", "ips": [{"ip": "203.0.113.8", "asn": "64500", "asn_name": "EXAMPLE-HOSTING", "country": "Germany"}]},
    ],
    "cname": [{"host": "www.example.com", "ips": [{"ip": "93.184.215.14", "asn": "15133", "asn_name": "EDGECAST", "country": "United States"}]}],
    "mx": [{"host": "10 mail.example.com", "ips": [{"ip": "198.51.100.5", "asn": "64501", "asn_name": "MAILCO", "country": "Netherlands"}]}],
    "ns": [{"host": "ns1.example.net", "ips": []}],
    "txt": ["v=spf1 -all", "google-site-verification=abc"],
    "total_a_recs": 5,
}


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setenv("SUBNETRY_REPORTS_DIR", str(tmp_path))
    monkeypatch.delenv(dnsdumpster.ENV_KEY, raising=False)
    monkeypatch.setattr(dnsdumpster, "MIN_INTERVAL", 0.05)
    dnsdumpster._cache.clear()
    yield tmp_path
    dnsdumpster._cache.clear()


def fake_api(status=200, body=SAMPLE, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(request)
        return httpx.Response(status, json=body) if body is not None else httpx.Response(status, text="<html>oops</html>")
    return httpx.MockTransport(handler)


def test_key_storage_never_echoes_the_key(dd, monkeypatch):
    assert dnsdumpster.status()["configured"] is False
    dnsdumpster.save_key(KEY)
    st = dnsdumpster.status()
    assert st == {"configured": True, "source": "settings", "hint": "…cdef", "signup_url": dnsdumpster.SIGNUP_URL}
    assert KEY not in json.dumps(st)
    assert json.loads((dd / ".subnetry-settings.json").read_text())["dnsdumpster_api_key"] == KEY
    monkeypatch.setenv(dnsdumpster.ENV_KEY, "env-key-0123456789abcdef")
    assert dnsdumpster.api_key() == ("env-key-0123456789abcdef", "env")
    monkeypatch.delenv(dnsdumpster.ENV_KEY)
    dnsdumpster.save_key("")
    assert dnsdumpster.status()["configured"] is False


def test_lookup_parses_and_summarizes(dd):
    dnsdumpster.save_key(KEY)
    calls = []
    r = asyncio.run(dnsdumpster.lookup("https://Example.com/path", transport=fake_api(calls=calls)))
    assert str(calls[0].url) == "https://api.dnsdumpster.com/domain/example.com"
    assert calls[0].headers["X-API-Key"] == KEY
    assert r["domain"] == "example.com" and r["cached"] is False
    assert r["counts"] == {"A": 3, "AAAA": 0, "CNAME": 1, "MX": 1, "NS": 1, "TXT": 2}
    mx = next(h for h in r["hosts"] if h["type"] == "MX")
    assert mx["host"] == "mail.example.com" and mx["priority"] == 10
    dev = next(h for h in r["hosts"] if h["host"] == "dev.example.com")
    assert dev["ips"][0]["banners"]["https"]["server"] == "nginx"
    assert r["unique_ips"] == 4 and tuple(r["asns"][0]) == ("EXAMPLE-HOSTING (AS64500)", 2)
    assert r["more_available"] is True and r["shown_a"] == 3 and r["total_a"] == 5
    assert r["notable"] == ["dev.example.com", "vpn.example.com"]


def test_cache_and_rate_limit(dd, monkeypatch):
    dnsdumpster.save_key(KEY)
    calls, sleeps = [], []
    real_sleep = asyncio.sleep

    async def spy_sleep(seconds):
        sleeps.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr(dnsdumpster.asyncio, "sleep", spy_sleep)

    async def run():
        t = fake_api(calls=calls)
        first = await dnsdumpster.lookup("example.com", transport=t)
        again = await dnsdumpster.lookup("example.com", transport=t)  # cached: no request
        other = await dnsdumpster.lookup("example.org", transport=t)  # must wait for the 2-second spacing
        return first, again, other

    first, again, other = asyncio.run(run())
    assert len(calls) == 2 and again["cached"] is True and other["domain"] == "example.org"
    assert sleeps and 0 < sleeps[-1] <= dnsdumpster.MIN_INTERVAL


@pytest.mark.parametrize("status,body,expected,code", [
    (401, {"error": "Invalid API key"}, "rejected the API key", 401),
    (429, {"error": "rate limited"}, "rate limit", 429),
    (200, {"error": "Domain not found"}, "Domain not found", 400),
    (500, None, "unexpected response", 502),
])
def test_errors(dd, status, body, expected, code):
    dnsdumpster.save_key(KEY)
    with pytest.raises(dnsdumpster.DumpsterError) as exc:
        asyncio.run(dnsdumpster.lookup("example.com", transport=fake_api(status, body)))
    assert expected in str(exc.value) and exc.value.status == code


def test_input_checks(dd):
    with pytest.raises(dnsdumpster.DumpsterError, match="API key first"):
        asyncio.run(dnsdumpster.lookup("example.com"))
    dnsdumpster.save_key(KEY)
    for ip in ("1.1.1.1", "2001:db8::1"):
        with pytest.raises(dnsdumpster.DumpsterError, match="not IP addresses"):
            asyncio.run(dnsdumpster.lookup(ip, transport=fake_api()))


def test_api_routes(dd):
    client = TestClient(app)
    assert client.get("/api/dnsdumpster/status").json()["configured"] is False
    assert client.get("/api/dnsdumpster", params={"q": "example.com"}).status_code == 400
    assert client.post("/api/dnsdumpster/key", json={"key": "short"}).status_code == 400
    st = client.post("/api/dnsdumpster/key", json={"key": KEY}).json()
    assert st["configured"] and KEY not in json.dumps(st)
    assert client.post("/api/dnsdumpster/key", json={"key": ""}).json()["configured"] is False
