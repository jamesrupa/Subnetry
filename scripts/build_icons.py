"""Render the Subnetry icon SVG to PNGs and pack them into .icns (macOS) and .ico (Windows).

Developer tool, not needed to run Subnetry: the generated files are committed.
Requires Playwright with Chromium:  python scripts/build_icons.py
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SVG = ROOT / "subnetry" / "static" / "brand" / "icon.svg"
OUT = ROOT / "subnetry" / "desktop"
STATIC = ROOT / "subnetry" / "static" / "brand"

# ICNS entry types holding PNG data, by pixel size (macOS picks the right one for each display).
ICNS_TYPES = [(b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128), (b"ic08", 256), (b"ic09", 512),
              (b"ic10", 1024), (b"ic11", 32), (b"ic12", 64), (b"ic13", 256), (b"ic14", 512)]
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]


def render(sizes: set[int]) -> dict[int, bytes]:
    from playwright.sync_api import sync_playwright

    svg = SVG.read_text()
    out = {}
    with sync_playwright() as p:
        kwargs = {"executable_path": sys.argv[1]} if len(sys.argv) > 1 else {}
        browser = p.chromium.launch(**kwargs)
        for size in sorted(sizes):
            page = browser.new_page(viewport={"width": size, "height": size})
            sized = svg.replace("<svg ", f'<svg width="{size}" height="{size}" ', 1)
            page.set_content(f"<html><body style='margin:0;background:transparent'>{sized}</body></html>")
            out[size] = page.screenshot(omit_background=True, clip={"x": 0, "y": 0, "width": size, "height": size})
            page.close()
        browser.close()
    return out


def build_icns(pngs: dict[int, bytes]) -> bytes:
    body = b"".join(kind + struct.pack(">I", len(pngs[size]) + 8) + pngs[size] for kind, size in ICNS_TYPES)
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def png_to_rgba(png: bytes) -> tuple[int, int, bytes]:
    """Decode an 8-bit RGBA, non-interlaced PNG (what Chromium screenshots are) to raw RGBA rows."""
    width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", png[16:29])
    if (depth, color, interlace) != (8, 6, 0):
        raise ValueError("expected an 8-bit RGBA, non-interlaced PNG")
    pos, idat = 8, b""
    while pos < len(png):
        length, kind = struct.unpack(">I4s", png[pos:pos + 8])
        if kind == b"IDAT":
            idat += png[pos + 8:pos + 8 + length]
        pos += 12 + length
    raw, stride, bpp = zlib.decompress(idat), width * 4, 4
    rows, prev = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b, c = prev[i], (prev[i - bpp] if i >= bpp else 0)
            if kind == 1:
                line[i] = (line[i] + a) & 255
            elif kind == 2:
                line[i] = (line[i] + b) & 255
            elif kind == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif kind == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(bytes(line))
        prev = line
    return width, height, b"".join(rows)


def rgba_to_dib(width: int, height: int, rgba: bytes) -> bytes:
    """A 32-bit BMP icon image: header, BGRA pixels bottom-up, then the 1-bit transparency mask."""
    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    stride = width * 4
    pixels = bytearray()
    for y in reversed(range(height)):
        row = rgba[y * stride:(y + 1) * stride]
        for x in range(0, stride, 4):
            r, g, b, a = row[x:x + 4]
            pixels += bytes((b, g, r, a))
    mask_stride = ((width + 31) // 32) * 4
    mask = bytearray()
    for y in reversed(range(height)):
        line = bytearray(mask_stride)
        for x in range(width):
            if rgba[y * stride + x * 4 + 3] == 0:  # fully transparent
                line[x // 8] |= 0x80 >> (x % 8)
        mask += line
    return header + bytes(pixels) + bytes(mask)


def build_ico(pngs: dict[int, bytes]) -> bytes:
    """Classic BMP images rather than embedded PNGs: Windows' .NET Icon class (used for the
    pywebview window icon) rejects PNG-compressed frames."""
    header = struct.pack("<HHH", 0, 1, len(ICO_SIZES))
    offset = len(header) + 16 * len(ICO_SIZES)
    entries, blobs = b"", b""
    for size in ICO_SIZES:
        data = rgba_to_dib(*png_to_rgba(pngs[size]))
        dim = 0 if size >= 256 else size  # 0 means 256 in the ICO format
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
        blobs += data
    return header + entries + blobs


def main() -> None:
    sizes = {s for _, s in ICNS_TYPES} | set(ICO_SIZES) | {180, 192}
    pngs = render(sizes)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "Subnetry.icns").write_bytes(build_icns(pngs))
    (OUT / "Subnetry.ico").write_bytes(build_ico(pngs))
    (OUT / "Subnetry.png").write_bytes(pngs[512])
    (STATIC / "icon-192.png").write_bytes(pngs[192])
    (STATIC / "apple-touch-icon.png").write_bytes(pngs[180])
    (STATIC / "favicon-32.png").write_bytes(pngs[32])
    print("wrote", ", ".join(str(p.relative_to(ROOT)) for p in [OUT / "Subnetry.icns", OUT / "Subnetry.ico", OUT / "Subnetry.png"]))


if __name__ == "__main__":
    main()
