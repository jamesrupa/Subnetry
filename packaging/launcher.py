"""Entry point of the packaged Subnetry app (PyInstaller).

Double-clicking the app opens the desktop window; command-line options (e.g. --no-browser --port 8799)
still work, which the build uses for a smoke test.
"""

import multiprocessing
import sys

from subnetry.__main__ import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.argv = [a for a in sys.argv if not a.startswith("-psn_")]  # very old macOS adds a process serial number
    if len(sys.argv) == 1:
        sys.argv.append("--app")
    main()
