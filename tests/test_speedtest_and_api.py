import asyncio
import json

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.testclient import TestClient

from subnetry.server import app
from subnetry.tools import speedtest

# A stand-in for speed.cloudflare.com's endpoints.
mock = FastAPI()


@mock.get("/__down")
async def down(bytes: int = 0):
    return Response(b"x" * min(bytes, 200_000), media_type="application/octet-stream")


@mock.post("/__up")
async def up(request: Request):
    async for _ in request.stream():
        pass
    return Response(b"ok")


async def collect(**kwargs):
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=mock))
    async with client:
        return [ev async for ev in speedtest.run_speedtest(base_url="http://mock", client=client, **kwargs)]


def test_speedtest_reports_every_phase():
    events = asyncio.run(collect(duration=1.5, streams=2, latency_pings=3))
    assert not [e for e in events if e["type"] == "error"], events
    done = events[-1]
    assert done["phase"] == "done"
    assert done["download_mbps"] > 0 and done["upload_mbps"] > 0 and done["latency_ms"] >= 0
    assert {e["phase"] for e in events if e["type"] == "sample"} >= {"latency", "download", "upload"}


def test_speedtest_reports_http_errors():
    async def run():
        transport = httpx.MockTransport(lambda req: httpx.Response(503))
        async with httpx.AsyncClient(transport=transport) as client:
            return [ev async for ev in speedtest.run_speedtest(base_url="http://mock", client=client)]
    events = asyncio.run(run())
    assert events[-1]["type"] == "error"


def test_jitter():
    assert speedtest.jitter([10, 12, 11, 15]) == (2 + 1 + 4) / 3
    assert speedtest.jitter([5]) == 0


client = TestClient(app)


def test_index_and_static():
    assert "Subnetry" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200


def test_overview():
    data = client.get("/api/overview").json()
    assert {"hostname", "interfaces", "networks", "gateway", "dns_servers"} <= data.keys()


def test_scan_rejects_public_range_as_event():
    with client.stream("GET", "/api/scan", params={"cidr": "8.8.8.0/24"}) as r:
        body = r.read().decode()
    events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: {\"")]
    assert events[0]["type"] == "error" and "private" in events[0]["message"]


def test_ports_rejects_public_host():
    assert client.get("/api/ports", params={"host": "8.8.8.8"}).status_code == 400


def test_cross_site_requests_blocked():
    assert client.get("/api/overview", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_port_scan_localhost_finds_listener():
    async def run():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            from subnetry.tools import netscan
            return port, await netscan.scan_ports("127.0.0.1", ports=[port, 1])
    port, result = asyncio.run(run())
    assert [p["port"] for p in result["open"]] == [port]


def test_ui_files_are_revalidated_after_updates():
    from fastapi.testclient import TestClient

    from subnetry.server import app

    client = TestClient(app)
    for path in ("/", "/static/app.js", "/static/styles.css"):
        r = client.get(path)
        assert r.status_code == 200 and r.headers["cache-control"] == "no-cache", path
    etag = client.get("/static/app.js").headers["etag"]
    assert client.get("/static/app.js", headers={"If-None-Match": etag}).status_code == 304  # still cheap


def test_index_links_versioned_assets(tmp_path, monkeypatch):
    import re

    from fastapi.testclient import TestClient

    from subnetry import server

    client = TestClient(server.app)
    html = client.get("/").text
    links = re.findall(r'"/static/([\w/.-]+\.(?:js|css))(\?v=\w+)?"', html)
    assert links and all(v for _, v in links), "every script/stylesheet link carries ?v=<hash>"
    assert client.get(f"/static/{links[0][0]}{links[0][1]}").status_code == 200
    # Changing a file changes its URL.
    monkeypatch.setattr(server, "STATIC_DIR", tmp_path)
    (tmp_path / "index.html").write_text('<script src="/static/app.js"></script>')
    (tmp_path / "app.js").write_text("one")
    first = client.get("/").text
    (tmp_path / "app.js").write_text("two")
    assert client.get("/").text != first
