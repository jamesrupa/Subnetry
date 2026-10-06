"""The macOS Wi-Fi helper flow, end to end, with fake swiftc / codesign / open executables."""

import asyncio
import json
import os
import stat
import sys
import textwrap
import time

import pytest

from subnetry.tools import macos, macos_helper, wifimonitor, wifiscan

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="fake tools are shebang scripts")

CURRENT = {"ssid": "HomeNet", "bssid": "a4:2b:b0:11:22:33", "rssi": -55, "noise": -92, "channel": 149, "band": 2,
           "tx_rate": 866.0, "interface": "en0"}
NETWORKS = [
    {"ssid": "HomeNet", "bssid": "a4:2b:b0:11:22:33", "rssi": -55, "noise": -92, "channel": 149, "band": 2,
     "security": "WPA2/WPA3 Personal", "current": True},
    {"ssid": "Neighbor", "bssid": "c0:ff:ee:00:00:01", "rssi": -71, "noise": -92, "channel": 6, "band": 1, "security": "WPA2 Personal"},
]


def write_tool(path, body):
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def fake_mac(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    state = tmp_path / "auth.txt"
    state.write_text("not_determined")
    builds = tmp_path / "builds.txt"
    write_tool(bin_dir / "swiftc", f"""
        import sys, pathlib
        out = sys.argv[sys.argv.index("-o") + 1]
        pathlib.Path(out).write_text("binary"); pathlib.Path(out).chmod(0o755)
        with open({str(builds)!r}, "a") as f: f.write("x")
        """)
    write_tool(bin_dir / "codesign", "import sys; sys.exit(0)\n")
    write_tool(bin_dir / "open", f"""
        import sys, json, os, time, pathlib
        args = sys.argv[sys.argv.index("--args") + 1:]
        mode, out = args[0], args[1]
        state = pathlib.Path({str(state)!r})
        auth = state.read_text()
        granted = auth == "authorized"
        cur = {CURRENT!r}
        if not granted:
            cur = {{k: v for k, v in cur.items() if k not in ("ssid", "bssid")}}
        result = {{"auth": auth, "services_enabled": True}}
        if mode == "auth":
            state.write_text("authorized"); result["auth"] = "authorized"
        elif mode == "scan":
            nets = {NETWORKS!r}
            if not granted:
                nets = [{{k: v for k, v in n.items() if k not in ("ssid", "bssid", "current")}} for n in nets]
            result["networks"] = nets; result["current"] = cur
        elif mode == "monitor":
            interval, stop = float(args[2]), args[3]
            t0 = time.time()
            while not os.path.exists(stop) and time.time() - t0 < 20:
                with open(out, "a") as f:
                    f.write(json.dumps({{"t": time.time() - t0, "auth": auth, "current": cur}}) + "\\n")
                time.sleep(interval)
            sys.exit(0)
        json.dump(result, open(out, "w"))
        """)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SUBNETRY_SUPPORT_DIR", str(tmp_path / "support"))
    monkeypatch.setattr(macos_helper, "IS_MAC", True)
    monkeypatch.setattr(wifimonitor, "IS_MAC", True)
    monkeypatch.setattr(macos, "_on_mac", lambda: True)
    return {"state": state, "builds": builds, "tmp": tmp_path}


def test_build_once_and_rebuild_on_source_change(fake_mac, monkeypatch):
    app = macos_helper.ensure_built()
    assert (app / "Contents" / "MacOS" / macos_helper.EXECUTABLE).is_file()
    assert (app / "Contents" / "Info.plist").is_file()
    macos_helper.ensure_built()
    assert fake_mac["builds"].read_text() == "x"  # cached
    monkeypatch.setattr(macos_helper, "source_hash", lambda: "changed")
    macos_helper.ensure_built()
    assert fake_mac["builds"].read_text() == "xx"


def test_rosetta_python_builds_natively(fake_mac):
    """Under Rosetta, swiftc must be started with `arch -arm64` (its build libraries are arm64-only)."""
    bin_dir = fake_mac["tmp"] / "bin"
    calls = fake_mac["tmp"] / "arch.txt"
    write_tool(bin_dir / "sysctl", "print('1')\n")
    write_tool(bin_dir / "arch", f"""
        import sys, os
        open({str(calls)!r}, "w").write(" ".join(sys.argv[1:3]))
        os.execv(sys.argv[2], sys.argv[2:])
        """)
    macos_helper.ensure_built()
    assert calls.read_text() == f"-arm64 {bin_dir / 'swiftc'}"
    assert fake_mac["builds"].read_text() == "x"


def test_sdk_mismatch_falls_back_to_an_older_sdk(fake_mac, monkeypatch, tmp_path):
    """A compiler older than the default SDK fails; retrying with an installed older SDK works."""
    sdks = tmp_path / "SDKs"
    for name in ("MacOSX15.4.sdk", "MacOSX26.sdk", "MacOSX15.sdk"):
        (sdks / name).mkdir(parents=True)
    (sdks / "MacOSX.sdk").symlink_to(sdks / "MacOSX26.sdk")
    monkeypatch.setattr(macos_helper, "CLT_SDKS", sdks)
    assert [p.rsplit("/", 1)[-1] for p in macos_helper._sdk_candidates()] == ["MacOSX26.sdk", "MacOSX15.4.sdk", "MacOSX15.sdk"]
    tried = tmp_path / "tried.txt"
    write_tool(fake_mac["tmp"] / "bin" / "swiftc", f"""
        import sys, pathlib
        sdk = sys.argv[sys.argv.index("-sdk") + 1] if "-sdk" in sys.argv else "default"
        with open({str(tried)!r}, "a") as f: f.write(pathlib.Path(sdk).name + "\\n")
        if not sdk.endswith("MacOSX15.4.sdk"):
            sys.stderr.write("<unknown>:0: error: failed to build module 'Swift'; this SDK is not supported by the compiler\\n"
                             + "-enable-experimental-feature X " * 200)
            sys.exit(1)
        out = sys.argv[sys.argv.index("-o") + 1]
        pathlib.Path(out).write_text("binary")
        """)
    assert macos_helper.ensure_built().is_dir()
    assert tried.read_text().split() == ["default", "MacOSX26.sdk", "MacOSX15.4.sdk"]


def test_compiler_errors_are_summarized(fake_mac, monkeypatch, tmp_path):
    monkeypatch.setattr(macos_helper, "CLT_SDKS", tmp_path / "none")
    write_tool(fake_mac["tmp"] / "bin" / "swiftc", """
        import sys
        sys.stderr.write("<unknown>:0: error: failed to build module 'Swift'; this SDK is not supported by the compiler\\n"
                         + "-enable-experimental-feature X " * 200)
        sys.exit(1)
        """)
    with pytest.raises(macos_helper.HelperUnavailable) as exc:
        macos_helper.ensure_built()
    msg = str(exc.value)
    assert "this SDK is not supported" in msg and "experimental-feature" not in msg and "Software Update" in msg


def test_native_python_builds_directly(fake_mac):
    write_tool(fake_mac["tmp"] / "bin" / "sysctl", "print('0')\n")
    assert macos_helper._native_prefix() == []


def test_missing_compiler_is_explained(fake_mac, monkeypatch):
    monkeypatch.setattr(macos_helper, "_find_swiftc", lambda: None)
    with pytest.raises(macos_helper.HelperUnavailable, match="xcode-select --install"):
        macos_helper.ensure_built()
    st = macos.location_status()
    assert "xcode-select" in st["helper_error"]


def test_permission_flow_and_scan(fake_mac):
    assert macos.location_status()["status"] == "not_determined"
    nets, auth = macos_helper.scan()
    assert auth == "not_determined" and all(n["redacted"] for n in nets)

    granted = macos.request_location()
    assert granted["status"] == "authorized" and granted["via"] == "helper"

    result = asyncio.run(wifiscan._scan_mac())
    home = next(n for n in result if n["in_use"])
    assert home["ssid"] == "HomeNet" and home["bssid"] == "A4:2B:B0:11:22:33" and home["band"] == "5 GHz"
    assert home["security"] == "WPA2/WPA3 Personal" and not home["redacted"]
    assert next(n for n in result if n["ssid"] == "Neighbor")["band"] == "2.4 GHz"


def test_connected_network_is_matched_without_bssid():
    data = {"networks": [{"ssid": "HomeNet", "rssi": -50, "channel": 36, "band": 2}],
            "current": {"ssid": "HomeNet", "rssi": -50, "channel": 36, "band": 2}}
    nets = macos_helper.networks_from_scan(data)
    assert len(nets) == 1 and nets[0]["in_use"]


def test_monitor_stream(fake_mac):
    fake_mac["state"].write_text("authorized")
    stream = macos_helper.MonitorStream(0.2)
    try:
        assert asyncio.run(macos_helper.wait_for_first(stream, timeout=10))
        first_pos = stream._pos
        time.sleep(0.6)
        latest = stream.read()
        assert stream._pos > first_pos and latest["current"]["ssid"] == "HomeNet"
        conn = macos_helper.to_connection(latest["current"])
        assert conn["signal_dbm"] == -55 and conn["tx_rate_mbps"] == 866.0 and conn["bssid"] == "A4:2B:B0:11:22:33"
    finally:
        stream.close()
    assert stream.proc.poll() is not None  # helper stopped via the stop file


def test_wifi_monitor_uses_helper_on_mac(fake_mac, monkeypatch):
    fake_mac["state"].write_text("authorized")

    async def no_scan():
        raise wifiscan.WifiError("skip")
    monkeypatch.setattr(wifimonitor.wifiscan, "scan_wifi", no_scan)

    async def run():
        out = []
        async for ev in wifimonitor.monitor(interval=0.2, scan_every=60, max_seconds=1.5):
            out.append(ev)
        return out
    samples = [e for e in asyncio.run(run()) if e["type"] == "sample"]
    assert samples and samples[-1]["ssid"] == "HomeNet" and samples[-1]["bssid"] == "A4:2B:B0:11:22:33"


def test_prebuilt_helper_is_used_without_compiling(fake_mac, monkeypatch, tmp_path):
    """The downloadable app ships the helper ready-made: no Swift compiler needed on the user's Mac."""
    prebuilt = tmp_path / "prebuilt" / macos_helper.APP_NAME
    (prebuilt / "Contents" / "MacOS").mkdir(parents=True)
    (prebuilt / "Contents" / "MacOS" / macos_helper.EXECUTABLE).write_text("binary")
    monkeypatch.setattr(macos_helper, "PREBUILT", prebuilt)
    monkeypatch.setattr(macos_helper, "_find_swiftc", lambda: None)  # would fail if it tried to compile
    app = macos_helper.ensure_built()
    assert (app / "Contents" / "MacOS" / macos_helper.EXECUTABLE).read_text() == "binary"
    assert not fake_mac["builds"].exists()
