"""Windows: request a fresh Wi-Fi scan (WlanScan) before reading netsh's cached list.

wlanapi.dll only exists on Windows, so a fake stands in for it; the ctypes structures,
pointer handling and notification callback in request_windows_scan are the real code.
"""

import asyncio
import ctypes
import sys
import threading

import pytest

from subnetry.system import CmdResult
from subnetry.tools import wifiscan


class FakeWlan:
    """Mimics the parts of the Native Wi-Fi API that request_windows_scan uses."""

    def __init__(self, adapters=2, notify=True, scan_result=0):
        self.adapters, self.notify, self.scan_result = adapters, notify, scan_result
        self.scanned, self.freed, self.closed, self.callback = [], 0, False, None
        self._keep = []

    def WlanOpenHandle(self, client_version, reserved, p_version, p_handle):
        p_handle._obj.value = 42
        return 0

    def WlanEnumInterfaces(self, handle, reserved, pp_list):
        ptr = pp_list._obj
        list_type = type(ptr)._type_
        info_type = list_type._fields_[2][1]._type_
        buf = ctypes.create_string_buffer(ctypes.sizeof(list_type) + ctypes.sizeof(info_type) * self.adapters)
        self._keep.append(buf)
        lst = list_type.from_buffer(buf)
        lst.dwNumberOfItems = self.adapters
        first = ctypes.addressof(lst.InterfaceInfo)
        for i in range(self.adapters):
            info = info_type.from_address(first + i * ctypes.sizeof(info_type))
            info.InterfaceGuid.Data1 = 1000 + i
            info.strInterfaceDescription = f"Wi-Fi adapter {i}"
        ctypes.memmove(ctypes.addressof(ptr), ctypes.byref(ctypes.c_void_p(ctypes.addressof(lst))), ctypes.sizeof(ctypes.c_void_p))
        return 0

    def WlanFreeMemory(self, p):
        self.freed += 1

    def WlanRegisterNotification(self, handle, source, ignore_dupes, callback, context, reserved, prev):
        self.callback = callback if source else None
        return 0 if self.notify else 5

    def WlanScan(self, handle, p_guid, ssid, ie, reserved):
        guid = type(p_guid._obj).from_buffer_copy(p_guid._obj)
        self.scanned.append(guid.Data1)
        if self.scan_result == 0 and self.notify:
            cb = self.callback
            data_type = type(cb)._argtypes_[0]._type_

            def fire():
                data = data_type(NotificationSource=0x08, NotificationCode=7, InterfaceGuid=guid)
                cb(ctypes.pointer(data), None)

            threading.Timer(0.05, fire).start()
        return self.scan_result

    def WlanCloseHandle(self, handle, reserved):
        self.closed = True
        return 0


@pytest.fixture
def windows(monkeypatch):
    def install(fake):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(ctypes, "WinDLL", lambda name: fake, raising=False)
        monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
        return fake
    return install


def test_scans_every_adapter_and_waits_for_completion(windows):
    fake = windows(FakeWlan(adapters=2))
    assert wifiscan.request_windows_scan(timeout=3) is True
    assert fake.scanned == [1000, 1001]
    assert fake.freed == 1 and fake.closed and fake.callback is None  # unregistered and closed


def test_times_out_without_notifications(windows, monkeypatch):
    slept = []
    monkeypatch.setattr(wifiscan.time, "sleep", slept.append)
    fake = windows(FakeWlan(adapters=1, notify=False))
    assert wifiscan.request_windows_scan(timeout=0.2) is True
    assert slept == [4] and fake.closed


def test_no_adapters_or_failed_scan(windows):
    windows(FakeWlan(adapters=0))
    assert wifiscan.request_windows_scan(timeout=0.2) is False
    fake = windows(FakeWlan(adapters=1, scan_result=1168))
    assert wifiscan.request_windows_scan(timeout=0.2) is False and fake.closed


def test_not_windows_does_nothing():
    assert wifiscan.request_windows_scan() is False


def test_windows_scan_refreshes_before_reading_netsh(monkeypatch):
    order = []
    monkeypatch.setattr(wifiscan, "request_windows_scan", lambda: order.append("scan") or True)

    async def fake_run(args, timeout=10):
        order.append(" ".join(args[2:4]))
        return CmdResult(0, "", "")

    monkeypatch.setattr(wifiscan, "run_cmd", fake_run)
    asyncio.run(wifiscan._scan_windows())
    assert order == ["scan", "show interfaces", "show networks"]
