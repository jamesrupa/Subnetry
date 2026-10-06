"""Setup page: tool status, install methods per platform, and the Speedtest CLI download."""

import asyncio
import io
import sys
import tarfile
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from subnetry.server import app
from subnetry.tools import setup

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake speedtest is a shell script")

FAKE_SPEEDTEST = b"#!/bin/sh\necho 'Speedtest by Ookla 1.2.0.84 (ea6b6773cf)'\n"


def tgz(name, data):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for n, d in (("speedtest.md", b"readme"), (name, data)):
            info = tarfile.TarInfo(n)
            info.size = len(d)
            t.addfile(info, io.BytesIO(d))
    return buf.getvalue()


def zipped(name, data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("speedtest.md", "readme")
        z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "tools_bin_dir", lambda: tmp_path / "bin")
    return tmp_path


def run(gen):
    async def collect():
        return [ev async for ev in gen]
    return asyncio.run(collect())


def test_speedtest_download_tgz(home, monkeypatch):
    monkeypatch.setattr(setup.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(setup.platform, "machine", lambda: "arm64")
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, content=tgz("speedtest", FAKE_SPEEDTEST))

    events = run(setup.install_speedtest(httpx.MockTransport(handler)))
    assert seen == ["https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-macosx-universal.tgz"]
    exe = home / "bin" / "speedtest"
    assert exe.read_bytes() == FAKE_SPEEDTEST and exe.stat().st_mode & 0o111
    assert events[-1]["line"].startswith("Speedtest by Ookla")


def test_speedtest_download_zip_layout(home, monkeypatch):
    # Windows ships a zip; the program name differs, but the extraction logic is the same.
    monkeypatch.setattr(setup.platform, "system", lambda: "Windows")
    monkeypatch.setattr(setup.platform, "machine", lambda: "AMD64")

    async def fake_version(path, args):
        return "Speedtest by Ookla 1.2.0"

    monkeypatch.setattr(setup, "_version", fake_version)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, content=zipped("speedtest.exe", b"MZ fake exe"))

    run(setup.install_speedtest(httpx.MockTransport(handler)))
    assert seen[0].endswith("ookla-speedtest-1.2.0-win64.zip")
    assert (home / "bin" / "speedtest.exe").read_bytes() == b"MZ fake exe"


def test_speedtest_download_failures(home, monkeypatch):
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    monkeypatch.setattr(setup.platform, "machine", lambda: "x86_64")
    with pytest.raises(setup.SetupError, match="HTTP 404"):
        run(setup.install_speedtest(httpx.MockTransport(lambda r: httpx.Response(404))))
    with pytest.raises(setup.SetupError, match="didn't contain"):
        run(setup.install_speedtest(httpx.MockTransport(lambda r: httpx.Response(200, content=tgz("other", b"x")))))
    monkeypatch.setattr(setup.platform, "machine", lambda: "riscv64")
    with pytest.raises(setup.SetupError, match="No Speedtest CLI download"):
        run(setup.install_speedtest())


def test_install_methods_per_platform(monkeypatch):
    monkeypatch.setattr(setup, "IS_WINDOWS", True)
    monkeypatch.setattr(setup, "IS_MAC", False)
    monkeypatch.setattr(setup, "find_winget", lambda: r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\winget.exe")
    assert setup.install_method("nmap")["method"] == "winget"
    assert "Npcap and TShark" in setup.install_method("wireshark")["note"]
    cmd = setup.install_command("wireshark")
    assert cmd[1:5] == ["install", "-e", "--id", "WiresharkFoundation.Wireshark"] and "--interactive" in cmd

    monkeypatch.setattr(setup, "IS_WINDOWS", False)
    monkeypatch.setattr(setup, "IS_MAC", True)
    monkeypatch.setattr(setup, "find_brew", lambda: "/opt/homebrew/bin/brew")
    assert setup.install_command("nmap") == ["/opt/homebrew/bin/brew", "install", "nmap"]
    assert setup.install_method("wireshark")["method"] == "brew-terminal"

    monkeypatch.setattr(setup, "find_brew", lambda: None)
    link = setup.install_method("nmap")
    assert link["method"] == "link" and link["url"] == "https://nmap.org/download.html"
    with pytest.raises(setup.SetupError):
        setup.install_command("nmap")


def test_status_and_routes(monkeypatch):
    for tool in setup.TOOLS.values():
        monkeypatch.setitem(tool, "find", lambda: None)
    st = asyncio.run(setup.status())
    assert [t["id"] for t in st["tools"]] == ["speedtest", "nmap", "wireshark"]
    assert all(not t["installed"] and t["install"]["method"] for t in st["tools"])
    client = TestClient(app)
    assert client.get("/api/setup/status").status_code == 200
    assert client.get("/api/setup/install", params={"tool": "rm"}).status_code == 422


def test_install_tool_command_line(monkeypatch, capsys):
    from subnetry import __main__ as entry

    async def fake_install(tool):
        yield {"type": "log", "line": f"installing {tool}"}
        yield {"type": "done", "ok": True, "message": "Speedtest.net CLI is installed."}

    monkeypatch.setattr(setup, "install", fake_install)
    assert entry._install_tool("speedtest") == 0
    assert "installing speedtest" in capsys.readouterr().out

    async def failing(tool):
        raise setup.SetupError("Download failed (HTTP 503).")
        yield  # pragma: no cover

    monkeypatch.setattr(setup, "install", failing)
    assert entry._install_tool("speedtest") == 1
