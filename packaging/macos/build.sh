#!/usr/bin/env bash
# Build Subnetry.app and a drag-to-Applications .dmg on macOS.
#
#   bash packaging/macos/build.sh [arm64|intel]
#
# Needs: Python 3.10+ with the project's requirements, PyInstaller, and Xcode command-line tools
# (swiftc, codesign, hdiutil). Output: dist/Subnetry.app and dist/Subnetry-mac-<label>.dmg
set -euo pipefail

LABEL="${1:-$( [ "$(uname -m)" = "arm64" ] && echo arm64 || echo intel )}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
HELPER_NAME="Subnetry Wi-Fi Helper.app"
WORK="build/macos"
rm -rf "$WORK" dist/Subnetry.app dist/Subnetry "dist/Subnetry-mac-$LABEL.dmg"
mkdir -p "$WORK"

echo "==> Building the Wi-Fi helper"
HELPER="$WORK/$HELPER_NAME"
mkdir -p "$HELPER/Contents/MacOS"
cp subnetry/macos_helper/Info.plist "$HELPER/Contents/Info.plist"
swiftc -O subnetry/macos_helper/WiFiHelper.swift -o "$HELPER/Contents/MacOS/subnetry-wifi-helper" \
  -framework CoreWLAN -framework CoreLocation -framework AppKit
codesign --force --sign - "$HELPER"

echo "==> Building Subnetry.app"
python -m PyInstaller --noconfirm --clean packaging/subnetry.spec
APP="dist/Subnetry.app"
cp -R "$HELPER" "$APP/Contents/Resources/"
# Ad-hoc signature for the whole bundle (required on Apple Silicon; not a Developer ID, so first launch
# needs right-click > Open or System Settings > Privacy & Security > Open Anyway).
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "==> Smoke test"
SMOKE_HOME="$(mktemp -d)"
HOME="$SMOKE_HOME" "$APP/Contents/MacOS/Subnetry" --no-browser --port 8799 &
PID=$!
ok=""
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:8799/api/subnet?q=10.0.0.5/22" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:8799/" | grep -q "<title>Subnetry</title>" || ok=""
curl -fsS "http://127.0.0.1:8799/api/dns/explainers" >/dev/null || ok=""
kill "$PID" 2>/dev/null || true
if [ -z "$ok" ]; then
  echo "Smoke test failed. Log:"; cat "$SMOKE_HOME/Library/Logs/Subnetry.log" 2>/dev/null || true
  exit 1
fi
test -x "$APP/Contents/Resources/$HELPER_NAME/Contents/MacOS/subnetry-wifi-helper"

echo "==> Making the disk image"
DMG_DIR="$WORK/dmg"
mkdir -p "$DMG_DIR"
cp -R "$APP" "$DMG_DIR/"
ln -s /Applications "$DMG_DIR/Applications"
cat > "$DMG_DIR/First launch - read me.txt" <<'TXT'
Installing Subnetry
===================
1. Drag Subnetry onto the Applications folder.
2. Open Applications and double-click Subnetry.

The first time, macOS may say it "can't verify" Subnetry because it isn't from the App Store.
Click Done, then open System Settings > Privacy & Security, scroll down and click "Open Anyway"
next to Subnetry. (On older macOS: right-click Subnetry > Open > Open.) You only need to do this once.

When macOS asks, allow Subnetry to "find devices on your local network": the scanners need it.
Optional tools (Speedtest.net CLI, Nmap, Wireshark) can be installed from Subnetry's Setup page.
TXT
hdiutil create -volname "Subnetry" -srcfolder "$DMG_DIR" -ov -format UDZO "dist/Subnetry-mac-$LABEL.dmg"
echo "==> Done: dist/Subnetry-mac-$LABEL.dmg"
