# PyInstaller spec for the downloadable Subnetry app:  pyinstaller --noconfirm packaging/subnetry.spec
# Produces dist/Subnetry/ (Windows: Subnetry.exe + files) or dist/Subnetry.app (macOS).
import os
import re
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
VERSION = re.search(r'__version__ = "([^"]+)"', open(os.path.join(ROOT, "subnetry", "__init__.py")).read())[1]
ASSETS = os.path.join(ROOT, "subnetry", "desktop")

# Web UI, icons, the Wi-Fi helper's Swift source. (A prebuilt helper is added to the .app by build.sh.)
datas = [d for d in collect_data_files("subnetry") if "prebuilt" not in d[0]]
try:
    datas += copy_metadata("pywebview")  # pywebview reads its own version
except Exception:  # not installed (e.g. a Linux test build): the app falls back to the browser
    pass

# Loaded by name at runtime, so the analysis can't see them.
hiddenimports = collect_submodules("subnetry") + collect_submodules("uvicorn") + collect_submodules("dns")

a = Analysis(
    [os.path.join(SPECPATH, "launcher.py")],
    pathex=[ROOT],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "playwright", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="Subnetry",
    console=False,  # a window app; output goes to the log file
    icon=os.path.join(ASSETS, "Subnetry.icns" if sys.platform == "darwin" else "Subnetry.ico"),
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Subnetry")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="Subnetry.app",
        icon=os.path.join(ASSETS, "Subnetry.icns"),
        bundle_identifier="com.subnetry.app",
        version=VERSION,
        info_plist={
            "CFBundleName": "Subnetry",
            "CFBundleDisplayName": "Subnetry",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "LSMinimumSystemVersion": "11.0",
            "NSHighResolutionCapable": True,
            "LSApplicationCategoryType": "public.app-category.utilities",
            # macOS 15+ asks before an app talks to devices on the local network (scans, router checks).
            "NSLocalNetworkUsageDescription": "Subnetry scans your local network to find devices, check their open "
                                              "ports and test your router.",
            "NSLocationWhenInUseUsageDescription": "macOS only shows Wi-Fi network names to apps with Location access. "
                                                   "Subnetry never uses your location.",
        },
    )
