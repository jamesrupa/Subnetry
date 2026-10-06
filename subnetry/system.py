"""Cross-platform helpers for running OS commands from async code."""

from __future__ import annotations

import asyncio
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

OS = platform.system()  # "Windows", "Darwin", "Linux"
IS_WINDOWS = OS == "Windows"
IS_MAC = OS == "Darwin"
IS_LINUX = OS == "Linux"
# True inside the packaged app (PyInstaller): there's no source checkout, Python or pip.
FROZEN = bool(getattr(__import__("sys"), "frozen", False))


def app_data_dir():
    """Per-user folder for Subnetry's own files (downloaded tools, window cache, helper app)."""
    import os
    from pathlib import Path

    if IS_WINDOWS:
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Subnetry"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "Subnetry"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "subnetry"


def tools_bin_dir():
    """Where Subnetry puts tools it downloads itself (e.g. the Speedtest.net CLI)."""
    return app_data_dir() / "bin"

# Subprocesses run in a dedicated thread pool instead of asyncio's subprocess API:
# it behaves the same under every event loop (uvicorn on Windows included) and lets
# a network sweep run many pings in parallel.
_executor = ThreadPoolExecutor(max_workers=64, thread_name_prefix="subnetry-cmd")


@dataclass
class CmdResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_cmd_sync(args: list[str], timeout: float = 10.0) -> CmdResult | None:
    """Run a command and capture its output. Returns None if it is not installed or times out."""
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return None
    return CmdResult(proc.returncode, proc.stdout or "", proc.stderr or "")


async def run_cmd(args: list[str], timeout: float = 10.0) -> CmdResult | None:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, run_cmd_sync, args, timeout)


async def run_blocking(func, *args):
    """Run any blocking callable (DNS lookups, etc.) in the shared pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, func, *args)


def find_tool(name: str, extra_paths: list[str] = ()) -> str | None:
    """Locate an external program on PATH or in its usual install folders."""
    import shutil
    from pathlib import Path

    found = shutil.which(name)
    if found:
        return found
    for p in extra_paths:
        if Path(p).is_file():
            return p
    return None


async def stream_cmd(args: list[str]):
    """Run a long-lived command, yielding ('out'|'err', line) as it prints.

    The process is killed if the consumer stops early (e.g. the browser tab closes).
    Finishes with ('exit', returncode).
    """
    import threading

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace", bufsize=1, **kwargs,
    )

    def pump(stream, kind):
        try:
            for line in stream:
                loop.call_soon_threadsafe(queue.put_nowait, (kind, line.rstrip("\r\n")))
            loop.call_soon_threadsafe(queue.put_nowait, (kind, None))
        except (RuntimeError, ValueError):  # loop closed / pipe closed after the consumer stopped
            pass

    for stream, kind in ((proc.stdout, "out"), (proc.stderr, "err")):
        threading.Thread(target=pump, args=(stream, kind), daemon=True).start()
    try:
        open_streams = 2
        while open_streams:
            kind, line = await queue.get()
            if line is None:
                open_streams -= 1
            else:
                yield kind, line
        yield "exit", await loop.run_in_executor(_executor, proc.wait)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                await loop.run_in_executor(_executor, proc.wait, 3)
            except subprocess.TimeoutExpired:
                proc.kill()


def raise_open_file_limit(target: int = 4096) -> int:
    """Raise this process's open-file limit (macOS defaults to 256, too low for parallel scans).

    Returns the resulting soft limit. Each probe uses one socket (a file descriptor).
    """
    try:
        import resource
    except ImportError:  # Windows has no such limit
        return target
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = target if hard == resource.RLIM_INFINITY else min(target, hard)
    if soft != resource.RLIM_INFINITY and soft < wanted:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
            soft = wanted
        except (ValueError, OSError):
            pass
    return target if soft == resource.RLIM_INFINITY else soft


def safe_concurrency(sockets_per_task: int, wanted: int) -> int:
    """How many tasks can run at once without running out of file descriptors."""
    limit = raise_open_file_limit()
    return max(4, min(wanted, (limit - 64) // max(1, sockets_per_task + 1)))
