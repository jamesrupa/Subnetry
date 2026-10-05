"""Subnetry as a desktop app: a native window (pywebview) and an installable launcher.

  python -m subnetry --app            open Subnetry in its own window
  python -m subnetry --install-app    add Subnetry to Applications (macOS), the Start menu + Desktop
                                    (Windows) or the app menu (Linux), with the Subnetry icon
  python -m subnetry --uninstall-app  remove that launcher again

The launcher runs this same Python environment, so it always uses your current copy of Subnetry.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
ASSETS = PACKAGE_DIR / "desktop"
APP_ID = "com.subnetry.desktop"

WEBVIEW_HELP = ("The desktop window needs pywebview: run `pip install -r requirements.txt` "
                "(on Linux also install GTK/WebKit, e.g. `sudo apt install python3-gi gir1.2-webkit2-4.1`, "
                "then `pip install pywebview`).")


# --- window ----------------------------------------------------------------------------

def _port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def pick_port(host: str, preferred: int, attempts: int = 10) -> int:
    """The preferred port (keeps saved settings like the theme), or the next free one."""
    for port in range(preferred, preferred + attempts):
        if _port_free(host, port):
            return port
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def wait_for_server(host: str, port: int, timeout: float = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _brand_macos_process() -> None:
    """Show Subnetry's name and icon in the Dock/menu bar instead of Python's (best effort)."""
    try:
        from AppKit import NSApplication, NSImage  # type: ignore[import-not-found]
        from Foundation import NSBundle  # type: ignore[import-not-found]

        info = NSBundle.mainBundle().infoDictionary()
        if info is not None:
            info["CFBundleName"] = "Subnetry"
        icon = NSImage.alloc().initWithContentsOfFile_(str(ASSETS / "Subnetry.icns"))
        if icon is not None:
            NSApplication.sharedApplication().setApplicationIconImage_(icon)
    except Exception:
        pass


WINDOW_TIMEOUT = 20  # seconds to wait for the window before falling back to the browser


def _log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def _pywebview_version() -> str:
    try:
        from importlib.metadata import version

        return version("pywebview")
    except Exception:
        return "?"


def _serve_in_browser(url: str, server_thread: threading.Thread, open_browser: bool) -> None:
    """The window didn't work: keep serving Subnetry for the default browser until the user stops it."""
    if open_browser:
        import webbrowser

        webbrowser.open(url)
        _log(f"Opened {url} in your browser instead.")
    if sys.platform == "win32" and (sys.stdout is None or not sys.stdout.isatty()):
        from .__main__ import log_path, show_error

        # No console to press Ctrl+C in: the message box keeps Subnetry running until it's dismissed.
        show_error(f"The Subnetry window couldn't open, so Subnetry is running in your web browser instead "
                   f"({url}).\n\nClick OK to stop Subnetry.\n\nDetails are in {log_path()}")
        return
    print("Press Ctrl+C to stop Subnetry.", flush=True)
    try:
        while server_thread.is_alive():
            server_thread.join(1)
    except KeyboardInterrupt:
        pass


def window_icon(platform: str | None = None) -> Path:
    """Windows' .NET Icon class only accepts .ico files (a PNG crashes the whole window)."""
    return ASSETS / ("Subnetry.ico" if (platform or sys.platform) == "win32" else "Subnetry.png")


def run_window(host: str = "127.0.0.1", port: int = 8765) -> bool:
    """Run the server in the background and show it in a native window. False if pywebview is missing."""
    import logging
    import platform

    warning = protected_location_warning()
    if warning:
        raise RuntimeError(warning)
    _log(f"Starting the desktop window: Python {platform.python_version()} ({sys.executable}), "
         f"{platform.platform()}, pywebview {_pywebview_version()}")
    try:
        import webview  # type: ignore[import-not-found]
    except ImportError as exc:
        _log(f"pywebview isn't available: {exc}")
        return False
    import uvicorn

    port = pick_port(host, port)
    url = f"http://{host}:{port}/"
    config = uvicorn.Config("subnetry.server:app", host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="subnetry-server", daemon=True)
    thread.start()
    if not wait_for_server(host, port):
        server.should_exit = True
        raise RuntimeError(f"Subnetry's server didn't start on port {port}; see the messages above.")
    _log(f"Server ready at {url}")

    if sys.platform == "darwin":
        _brand_macos_process()
    if sys.stderr is None or not sys.stderr.isatty():
        logging.getLogger("pywebview").setLevel(logging.DEBUG)  # which renderer it picked, and why, goes to the log
    for key, value in (("ALLOW_DOWNLOADS", True), ("OPEN_EXTERNAL_LINKS_IN_BROWSER", True)):
        try:
            webview.settings[key] = value  # pywebview 5+: report exports save normally, links open in your browser
        except (AttributeError, TypeError):
            pass
    # A new address each launch: the window's web engine (WebKit on macOS) can't reuse a cached
    # page from before an update.
    window = webview.create_window("Subnetry", f"{url}?launch={int(time.time())}", width=1400, height=900, min_size=(900, 600),
                                   background_color="#060a12", text_select=True)
    shown = getattr(getattr(window, "events", None), "shown", None)
    fell_back = threading.Event()

    def watchdog() -> None:
        if shown is not None and not shown.wait(WINDOW_TIMEOUT):
            fell_back.set()
            _log(f"The window still hasn't appeared after {WINDOW_TIMEOUT} s.")
            if sys.platform == "win32" and (sys.stdout is None or not sys.stdout.isatty()):
                _serve_in_browser(url, thread, open_browser=True)  # returns when the message box is dismissed
                _log("Stopped from the message box.")
                os._exit(0)  # the window loop is stuck, so end the whole process
            import webbrowser

            webbrowser.open(url)
            _log(f"Opened {url} in your browser instead.")
        elif shown is not None:
            _log("Window shown.")

    threading.Thread(target=watchdog, name="subnetry-window-watchdog", daemon=True).start()
    # Keep browser storage between runs (theme choice etc.); pywebview defaults to a private session.
    storage = Path.home() / (".subnetry" if sys.platform != "darwin" else "Library/Application Support/Subnetry") / "webview"
    storage.mkdir(parents=True, exist_ok=True)
    options = {"private_mode": False, "storage_path": str(storage), "icon": str(window_icon())}
    _log("Opening the window…")
    while True:  # older pywebview versions lack some options: drop them one by one
        try:
            webview.start(**options)
            break
        except TypeError as exc:
            bad = next((k for k in options if k in str(exc)), None)
            if bad is None:
                raise
            options.pop(bad)
        except Exception as exc:  # e.g. no WebView2 / pythonnet on Windows, no GTK on Linux
            _log(f"The window couldn't start: {type(exc).__name__}: {exc}")
            break
    if shown is not None and not shown.is_set():
        _log("The window never appeared.")
        _serve_in_browser(url, thread, open_browser=not fell_back.is_set())
    else:
        _log("Window closed.")
    server.should_exit = True
    thread.join(timeout=5)
    return True


# --- launcher install ------------------------------------------------------------------

def _python_for_launcher() -> str:
    """The interpreter of this environment (pythonw on Windows so no console window appears)."""
    exe = Path(sys.executable)
    if sys.platform == "win32":
        candidate = exe.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(exe)


def macos_app_path(apps_dir: Path | None = None) -> Path:
    return (apps_dir or Path.home() / "Applications") / "Subnetry.app"


def build_macos_app(apps_dir: Path | None = None, python: str | None = None) -> Path:
    """A minimal .app bundle whose executable starts Subnetry's desktop window."""
    app = macos_app_path(apps_dir)
    if app.exists():
        shutil.rmtree(app)
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir()
    shutil.copy(ASSETS / "Subnetry.icns", app / "Contents" / "Resources" / "Subnetry.icns")
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({
            "CFBundleName": "Subnetry",
            "CFBundleDisplayName": "Subnetry",
            "CFBundleIdentifier": APP_ID,
            "CFBundleExecutable": "Subnetry",
            "CFBundleIconFile": "Subnetry",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": _version(),
            "CFBundleVersion": _version(),
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
        }, f)
    log = Path.home() / "Library" / "Logs" / "Subnetry.log"
    launcher = app / "Contents" / "MacOS" / "Subnetry"
    launcher.write_text(
        "#!/bin/bash\n"
        "# Starts Subnetry's desktop window with the Python environment it was installed from.\n"
        f'mkdir -p "{log.parent}"\n'
        f'cd "{PROJECT_DIR}" || exit 1\n'
        f'exec "{python or _python_for_launcher()}" -m subnetry --app >>"{log}" 2>&1\n'
    )
    launcher.chmod(0o755)
    return app


def _version() -> str:
    from . import __version__
    return __version__


def remove_legacy_launchers() -> list[str]:
    """Launchers created before the app was renamed from NetApp to Subnetry."""
    removed = []
    home = Path.home()
    legacy_app = home / "Applications" / "NetApp.app"
    try:
        is_ours = plistlib.loads((legacy_app / "Contents" / "Info.plist").read_bytes()).get("CFBundleIdentifier") == "com.netapp.desktop"
    except (OSError, plistlib.InvalidFileException, ValueError):
        is_ours = False
    if is_ours:
        shutil.rmtree(legacy_app)
        removed.append(str(legacy_app))
    others = [home / ".local" / "share" / "applications" / "netapp.desktop"]
    if sys.platform == "win32":
        others += [Path(os.environ["USERPROFILE"]) / "Desktop" / "NetApp.lnk",
                   Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "NetApp.lnk"]
    for path in others:
        if path.exists():
            path.unlink()
            removed.append(str(path))
    return removed


def protected_location_warning(project_dir: Path | None = None) -> str | None:
    """Subnetry cloned inside C:\\Windows (an Administrator PowerShell starts in System32): the window
    engine can't write its files there when the app runs as a normal user, so the window never opens."""
    if sys.platform != "win32":
        return None
    windir = Path(os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows")
    folder = (project_dir or PROJECT_DIR).resolve()
    try:
        folder.relative_to(windir.resolve())
    except ValueError:
        return None
    return (f"Subnetry is installed inside the Windows system folder ({folder}), probably because it was "
            "downloaded from an Administrator PowerShell. Windows protects that folder, so the app can't open "
            "its window there. Open a normal (non-Administrator) PowerShell and set Subnetry up again in your "
            "user folder: `cd $HOME`, then `git clone https://github.com/jamesrupa/subnetry.git` and the "
            "other setup steps.")


def install_launcher() -> str:
    warning = protected_location_warning()
    if warning:
        raise SystemExit(warning)
    legacy = remove_legacy_launchers()
    note = ("\nRemoved the old launcher(s) from before the rename: " + ", ".join(legacy)) if legacy else ""
    return _install_launcher() + note


def _install_launcher() -> str:
    if sys.platform == "darwin":
        app = build_macos_app()
        lsregister = ("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
                      "LaunchServices.framework/Support/lsregister")
        if os.path.exists(lsregister):  # refresh Finder/Dock so the icon shows straight away
            subprocess.run([lsregister, "-f", str(app)], capture_output=True)
        return (f"Installed {app}\nOpen it from Launchpad, Spotlight (\"Subnetry\") or Finder › Applications, "
                "and drag it to the Dock to keep it there.")
    if sys.platform == "win32":
        paths = []
        for folder in (Path(os.environ["USERPROFILE"]) / "Desktop",
                       Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"):
            lnk = folder / "Subnetry.lnk"
            script = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');"
                      f"$s.TargetPath='{_python_for_launcher()}';$s.Arguments='-m subnetry --app';"
                      f"$s.WorkingDirectory='{PROJECT_DIR}';$s.IconLocation='{ASSETS / 'Subnetry.ico'}';"
                      "$s.Description='Subnetry network diagnostics';$s.Save()")
            subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True, capture_output=True)
            paths.append(str(lnk))
        return "Created shortcuts:\n  " + "\n  ".join(paths)
    desktop = linux_desktop_entry()
    return f"Installed {desktop}\nSubnetry now appears in your applications menu."


def linux_desktop_entry(apps_dir: Path | None = None, python: str | None = None) -> Path:
    apps = apps_dir or Path.home() / ".local" / "share" / "applications"
    apps.mkdir(parents=True, exist_ok=True)
    path = apps / "subnetry.desktop"
    path.write_text(
        "[Desktop Entry]\nType=Application\nName=Subnetry\nComment=Network analysis & diagnostics\n"
        f'Exec=sh -c \'cd "{PROJECT_DIR}" && exec "{python or _python_for_launcher()}" -m subnetry --app\'\n'
        f"Icon={ASSETS / 'Subnetry.png'}\nTerminal=false\nCategories=Network;Utility;\n"
    )
    return path


def uninstall_launcher() -> str:
    removed = remove_legacy_launchers()
    targets = [macos_app_path(), Path.home() / ".local" / "share" / "applications" / "subnetry.desktop"]
    if sys.platform == "win32":
        targets += [Path(os.environ["USERPROFILE"]) / "Desktop" / "Subnetry.lnk",
                    Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Subnetry.lnk"]
    for t in targets:
        if t.is_dir():
            shutil.rmtree(t)
            removed.append(str(t))
        elif t.exists():
            t.unlink()
            removed.append(str(t))
    return "Removed:\n  " + "\n  ".join(removed) if removed else "Nothing to remove."
