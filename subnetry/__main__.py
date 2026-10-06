"""Launch the Subnetry dashboard: `python -m subnetry` (or the `subnetry` command)."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path


def log_path() -> Path:
    """Where the desktop app's messages go when there's no console to print them to."""
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "Subnetry" / "Subnetry.log"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "Subnetry.log"
    return Path.home() / ".subnetry" / "Subnetry.log"


def attach_log_if_windowless() -> Path | None:
    """Started without a console (pythonw.exe from the Start-menu shortcut), sys.stdout and
    sys.stderr are None: printing fails and uvicorn can't even set up its logging. Send both
    to a log file instead. Returns the log's path, or None when there is a console."""
    from .system import FROZEN

    # The packaged app has no console either: on macOS its output would go nowhere when opened from Finder.
    if sys.stdout is not None and sys.stderr is not None and not FROZEN:
        return None
    path = log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        log = open(path, "a", encoding="utf-8", buffering=1)
    except OSError:
        log = open(os.devnull, "w", encoding="utf-8")
    log.write(f"\n--- Subnetry started {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    try:
        import faulthandler

        faulthandler.enable(log)  # a crash inside native code (e.g. the window engine) still leaves a trace
    except (ImportError, ValueError, OSError):
        pass
    if sys.stdout is None or FROZEN:
        sys.stdout = log
    if sys.stderr is None or FROZEN:
        sys.stderr = log
    return path


def show_error(message: str) -> None:
    """A message box, so a failure is visible when the app was started without a console."""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, "Subnetry", 0x10)  # MB_ICONERROR
        except Exception:
            pass


def main() -> None:
    log = attach_log_if_windowless()
    try:
        _main()
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        traceback.print_exc()
        if log is None:
            raise
        show_error(f"Subnetry couldn't start:\n\n{exc}\n\nDetails are in {log}")
        sys.exit(1)


def _main() -> None:
    if sys.version_info < (3, 10):
        sys.exit(f"Subnetry needs Python 3.10 or newer (this is {sys.version.split()[0]}). "
                 "On macOS: `brew install python` or download it from python.org.")
    import uvicorn

    from .system import raise_open_file_limit

    raise_open_file_limit()  # macOS allows only 256 open sockets by default; scans need more

    parser = argparse.ArgumentParser(prog="subnetry", description="Network analysis & diagnostic toolkit")
    parser.add_argument("--host", default="127.0.0.1", help="interface to listen on (default: localhost only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser window")
    parser.add_argument("--reports-dir", help="where full-scan reports are saved (default: ~/Subnetry-Reports)")
    parser.add_argument("--app", action="store_true", help="open Subnetry in its own desktop window")
    parser.add_argument("--install-app", action="store_true",
                        help="add a Subnetry launcher (macOS Applications / Windows Start menu / Linux app menu)")
    parser.add_argument("--uninstall-app", action="store_true", help="remove that launcher")
    parser.add_argument("--install-tool", choices=["speedtest", "nmap", "wireshark"],
                        help="install an optional tool, as the Setup page does (used by the Windows installer)")
    args = parser.parse_args()
    if args.install_tool:
        sys.exit(_install_tool(args.install_tool))
    if args.reports_dir:
        os.environ["SUBNETRY_REPORTS_DIR"] = os.path.abspath(args.reports_dir)

    from . import desktop_app

    if args.install_app:
        print(desktop_app.install_launcher())
        return
    if args.uninstall_app:
        print(desktop_app.uninstall_launcher())
        return
    if args.app:
        if desktop_app.run_window(args.host, args.port):
            return
        print(desktop_app.WEBVIEW_HELP, "Opening Subnetry in your browser instead.", file=sys.stderr)

    url = f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}"
    print(f"Subnetry running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    from .server import app  # the object, not "subnetry.server:app": the packaged app can't import by name

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


def _install_tool(tool: str) -> int:
    import asyncio

    from .tools import setup

    async def run() -> bool:
        ok = False
        async for ev in setup.install(tool):
            if ev["type"] == "log":
                print(ev["line"], flush=True)
            elif ev["type"] == "done":
                print(ev["message"], flush=True)
                ok = ev["ok"]
        return ok

    try:
        return 0 if asyncio.run(run()) else 1
    except setup.SetupError as exc:
        print(f"Couldn't install {tool}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main()
