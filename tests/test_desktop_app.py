import plistlib
import sys
import types
import urllib.request

import pytest

from subnetry import desktop_app


def test_macos_bundle(tmp_path):
    app = desktop_app.build_macos_app(tmp_path, python="/venv/bin/python")
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleExecutable"] == "Subnetry" and info["CFBundleIconFile"] == "Subnetry"
    assert (app / "Contents" / "Resources" / "Subnetry.icns").read_bytes()[:4] == b"icns"
    launcher = app / "Contents" / "MacOS" / "Subnetry"
    text = launcher.read_text()
    assert launcher.stat().st_mode & 0o111 and '"/venv/bin/python" -m subnetry --app' in text
    assert f'cd "{desktop_app.PROJECT_DIR}"' in text
    desktop_app.build_macos_app(tmp_path, python="/venv/bin/python")  # reinstall replaces cleanly


def test_linux_desktop_entry(tmp_path):
    entry = desktop_app.linux_desktop_entry(tmp_path, python="/venv/bin/python")
    text = entry.read_text()
    assert "Name=Subnetry" in text and "-m subnetry --app" in text and "Subnetry.png" in text


def test_icons_present():
    assert (desktop_app.ASSETS / "Subnetry.ico").read_bytes()[:4] == b"\x00\x00\x01\x00"
    assert (desktop_app.ASSETS / "Subnetry.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_pick_port_skips_busy_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        busy = s.getsockname()[1]
        assert desktop_app.pick_port("127.0.0.1", busy) != busy


def test_run_window_serves_app_and_shuts_down(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    seen = {}
    fake = types.ModuleType("webview")
    fake.settings = {}

    def create_window(title, url, **kw):
        seen["title"], seen["url"] = title, url

    def start(**options):
        if "icon" in options:  # simulate an older pywebview without the icon option
            raise TypeError("start() got an unexpected keyword argument 'icon'")
        seen["options"] = options
        seen["page"] = urllib.request.urlopen(seen["url"], timeout=5).read().decode()

    fake.create_window, fake.start = create_window, start
    monkeypatch.setitem(sys.modules, "webview", fake)
    assert desktop_app.run_window("127.0.0.1", 18765)
    assert seen["title"] == "Subnetry" and "<title>Subnetry</title>" in seen["page"]
    assert "?launch=" in seen["url"]  # a fresh address each launch, so no stale cached page
    assert seen["options"]["private_mode"] is False and fake.settings["ALLOW_DOWNLOADS"] is True


def _fake_webview(monkeypatch, start):
    """A pywebview stand-in whose window has a real `shown` event."""
    import threading

    fake = types.ModuleType("webview")
    fake.settings = {}
    window = types.SimpleNamespace(events=types.SimpleNamespace(shown=threading.Event()))
    fake.create_window = lambda title, url, **kw: window
    fake.start = lambda **options: start(window)
    monkeypatch.setitem(sys.modules, "webview", fake)
    return window


def test_run_window_shown_normally(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    fallback = []
    monkeypatch.setattr(desktop_app, "_serve_in_browser", lambda *a, **k: fallback.append(k))
    _fake_webview(monkeypatch, lambda w: w.events.shown.set())
    assert desktop_app.run_window("127.0.0.1", 18766)
    out = capsys.readouterr().out
    assert not fallback and "Server ready at" in out and "Window closed." in out and "pywebview" in out


@pytest.mark.parametrize("problem", ["returns", "raises"])
def test_run_window_falls_back_to_browser(monkeypatch, tmp_path, capsys, problem):
    """If the window never appears (e.g. no WebView2 on Windows), Subnetry opens in the browser instead."""
    monkeypatch.setenv("HOME", str(tmp_path))
    fallback = []
    monkeypatch.setattr(desktop_app, "_serve_in_browser", lambda url, thread, open_browser: fallback.append((url, open_browser)))

    def start(window):
        if problem == "raises":
            raise RuntimeError("WebView2 runtime not found")

    _fake_webview(monkeypatch, start)
    assert desktop_app.run_window("127.0.0.1", 18767)
    assert fallback == [("http://127.0.0.1:18767/", True)]
    out = capsys.readouterr().out
    assert "The window never appeared." in out
    if problem == "raises":
        assert "WebView2 runtime not found" in out


def test_run_window_watchdog_opens_browser_when_stuck(monkeypatch, tmp_path, capsys):
    import time as _time

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(desktop_app, "WINDOW_TIMEOUT", 0.3)
    opened, fallback = [], []
    monkeypatch.setattr("webbrowser.open", opened.append)
    monkeypatch.setattr(desktop_app, "_serve_in_browser", lambda url, thread, open_browser: fallback.append(open_browser))
    _fake_webview(monkeypatch, lambda w: _time.sleep(1))  # a window loop that hangs for a while
    assert desktop_app.run_window("127.0.0.1", 18768)
    assert opened == ["http://127.0.0.1:18768/"]
    assert fallback == [False]  # browser already open: don't open a second tab
    assert "hasn't appeared after" in capsys.readouterr().out


def test_run_window_without_pywebview(monkeypatch):
    monkeypatch.setitem(sys.modules, "webview", None)  # import fails
    assert desktop_app.run_window() is False


def test_install_replaces_launcher_from_old_name(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    old = desktop_app.build_macos_app(tmp_path / "Applications", python="/venv/bin/python")
    # Make it look like the launcher an older version (named NetApp) installed.
    legacy = old.with_name("NetApp.app")
    old.rename(legacy)
    info = plistlib.loads((legacy / "Contents" / "Info.plist").read_bytes())
    info["CFBundleIdentifier"] = "com.netapp.desktop"
    (legacy / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
    unrelated = tmp_path / "Applications" / "Other.app"
    unrelated.mkdir()
    assert desktop_app.remove_legacy_launchers() == [str(legacy)]
    assert not legacy.exists() and unrelated.exists()


# --- started without a console (pythonw.exe from the Windows shortcut) ------------------------------

def test_windowless_start_logs_to_file(tmp_path, monkeypatch):
    from subnetry import __main__ as entry

    monkeypatch.setattr(entry, "log_path", lambda: tmp_path / "logs" / "Subnetry.log")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    path = entry.attach_log_if_windowless()
    assert path == tmp_path / "logs" / "Subnetry.log"
    print("hello from pythonw")
    import uvicorn
    uvicorn.Config("subnetry.server:app", log_level="warning").load()  # crashed with stdout=None
    sys.stdout.flush()
    assert "hello from pythonw" in path.read_text()


def test_console_start_is_left_alone(monkeypatch):
    from subnetry import __main__ as entry

    assert entry.attach_log_if_windowless() is None


def test_windowless_failure_shows_a_message(tmp_path, monkeypatch):
    from subnetry import __main__ as entry

    shown = []
    monkeypatch.setattr(entry, "attach_log_if_windowless", lambda: tmp_path / "Subnetry.log")
    monkeypatch.setattr(entry, "show_error", shown.append)
    monkeypatch.setattr(entry, "_main", lambda: (_ for _ in ()).throw(RuntimeError("no WebView2")))
    with pytest.raises(SystemExit):
        entry.main()
    assert "no WebView2" in shown[0] and "Subnetry.log" in shown[0]


def test_log_path_per_platform(monkeypatch, tmp_path):
    from subnetry import __main__ as entry

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert entry.log_path() == tmp_path / "Subnetry" / "Subnetry.log"
    monkeypatch.setattr(sys, "platform", "darwin")
    assert entry.log_path().parts[-3:] == ("Library", "Logs", "Subnetry.log")


def test_refuses_to_run_from_the_windows_folder(monkeypatch, tmp_path):
    windir = tmp_path / "Windows"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("WINDIR", str(windir))
    assert "Windows system folder" in desktop_app.protected_location_warning(windir / "System32" / "subnetry")
    assert desktop_app.protected_location_warning(tmp_path / "Users" / "me" / "subnetry") is None
    monkeypatch.setattr(desktop_app, "PROJECT_DIR", windir / "System32" / "subnetry")
    with pytest.raises(SystemExit, match="non-Administrator"):
        desktop_app.install_launcher()
    with pytest.raises(RuntimeError, match="Windows system folder"):
        desktop_app.run_window()


def test_window_icon_is_ico_on_windows():
    import struct

    ico = desktop_app.window_icon("win32")
    assert ico.suffix == ".ico" and desktop_app.window_icon("darwin").suffix == ".png"
    data = ico.read_bytes()
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1) and count >= 4
    for i in range(count):  # every frame a classic BMP (BITMAPINFOHEADER), not an embedded PNG
        w, h, _, _, planes, bits, size, offset = struct.unpack("<BBBBHHII", data[6 + 16 * i:22 + 16 * i])
        assert bits == 32 and offset + size <= len(data)
        assert struct.unpack("<I", data[offset:offset + 4])[0] == 40, f"frame {w or 256}px is not a BMP"
