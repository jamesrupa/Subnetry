# Subnetry: Network Analysis & Diagnostic Toolkit

A local network toolkit you run on your own computer and use from your browser.
It is a small Python server (FastAPI) and a plain HTML/JS dashboard. The server
does the work a browser can't, like sending pings, opening sockets and asking the OS
for nearby Wi-Fi networks. The dashboard shows the results live.

| Tool | What it does |
|---|---|
| **Dashboard** | The home screen: live connection status and latency (router, internet, DNS), a live Wi-Fi signal dial, and your latest speed test, health score, device count and top recommendations, with one-click quick actions. |
| **Health Check** | One-click **Quick scan** (speed test and Wi-Fi scan) or **Full scan** (speed test, traceroute to google.com, network scan saved to a file, a top-1000-port scan of every device, and Wi-Fi scan). Ends with a health score, a ranked "how to improve your score" plan and a prioritized list of recommended changes. Results export as HTML/JSON/CSV. |
| **Overview** | Hostname, local IP, default gateway, DNS servers, public IP and every network interface. |
| **Speed Test** | Ping, jitter, download, upload and packet loss using the official **Speedtest.net (Ookla) CLI**, with a server picker and a shareable result link. Falls back to Cloudflare's speed-test endpoints when the CLI isn't installed. Live throughput chart. |
| **Network Scanner** | Sweeps your LAN for devices using ICMP ping, TCP probes and the ARP table. Shows IP, hostname, MAC with its manufacturer (and flags private/randomized MACs), response time and a device-type guess (printer, NAS, camera, TV…). Devices with a web interface (router, printer, NAS) get a clickable IP that opens it in your browser. Can also run a common-ports scan on each device. |
| **Traceroute** | The route to any website or IP, hop by hop and live: each router's name, network owner (ASN) and country, three round-trip times and loss, a latency-per-hop chart and a route summary (Your network → ISP → … → destination). Explains where delay or loss starts, whether it's your Wi-Fi/router, your ISP or just distance, and when silent hops can be ignored. Uses the system's `traceroute` (macOS/Linux) or `tracert` (Windows). |
| **Public IP** | Your public IPv4/IPv6 address, ISP, ASN, approximate location, time zone and reverse DNS. Can also look up any other public IP. |
| **Port Scanner (Nmap)** | Runs [Nmap](https://nmap.org) with ready-made profiles (host discovery, top 100, top 1000 + versions, all ports) and optional OS detection and default scripts. Works on LAN ranges, **public IPs and hostnames** (public targets need you to confirm you own them or have permission; up to a /24). Shows live progress, per-device ports, software versions, MAC vendors, OS guesses and web-interface links, with the same security recommendations as the Health Check. |
| **Wi-Fi Monitor** | Live signal graph colored by access point, with a signal dial beside it. Catches roaming between APs and mesh nodes, disconnects, and "sticky" connections that cling to a weak AP while a much stronger one is nearby. Mark locations as you walk around to build a weak-spot survey, and export samples as CSV. |
| **Traffic Analyzer** | Live packet capture with Wireshark's engine (tshark), explained in plain English: protocol mix, busiest devices, which sites and services were contacted (from DNS and TLS names), a live activity feed and warnings such as unencrypted logins. Can save a `.pcapng` to open in Wireshark. A **Filter help** guide offers ready-made capture filters (filled in with your own addresses), a syntax cheat sheet and a Wireshark display-filter translation table, and the filter box spots display-filter syntax and offers the capture-filter equivalent. |
| **Wi-Fi Scanner** | Nearby access points with SSID, BSSID, signal (dBm and quality), channel, band and security. Channel-usage charts for **2.4, 5 and 6 GHz**, the quietest channel per band, and whether you should change the channel your own network uses. |
| **Subnet Calculator** | Network, broadcast, usable range, host count, netmask and wildcard for any IPv4 or IPv6 address (accepts `/24`, `255.255.255.0` and Cisco wildcard masks). Shows the network and host bits in binary, splits a network into smaller subnets, summarizes a list of networks into the fewest CIDR blocks, and has a /8–/32 cheat sheet. |
| **MAC Vendor Lookup** | Who made a device, from its MAC address (one or many at once). Works offline from Nmap's vendor list, or download the official IEEE registry (including the smaller MA-M/MA-S blocks). Explains private/randomized, multicast and broadcast addresses. The Network Scanner uses it too. |
| **Port Reference** | About 100 common ports: what uses them, whether they're encrypted and how risky they are to leave open, with search and filters. |
| **DNS Lookup** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA and HTTPS records (or reverse DNS for an IP) from your own DNS or Cloudflare/Google/Quad9, each explained in plain English. Decodes SPF and DMARC term by term, looks for DKIM keys, flags email-security gaps, and has explainers for every record type. Optionally adds **DNSDumpster** results: the domain's publicly known hosts and subdomains with their IP, network (ASN), country and reverse DNS, flagging names like dev/staging/admin/vpn (needs a free DNSDumpster API key). |

## Quick start

Requires **Python 3.10+**.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m subnetry
```

Your browser opens at <http://localhost:8765>. Options: `--port 9000` and `--no-browser`.
`--host 0.0.0.0` exposes the dashboard to other machines on your network, so use it with care.

You can also run `pip install -e .` to get a `subnetry` command.

### Desktop app

```bash
python -m subnetry --app            # open Subnetry in its own window instead of a browser tab
python -m subnetry --install-app    # add a Subnetry launcher with its icon
python -m subnetry --uninstall-app  # remove the launcher again
```

`--install-app` creates **Subnetry.app** in `~/Applications` on macOS (open it from Launchpad or Spotlight and drag it to
the Dock), Desktop and Start-menu shortcuts on Windows, or an app-menu entry on Linux. The launcher uses the Python
environment you ran it from, so `git pull` updates the app too. The window uses `pywebview` (installed by
`requirements.txt` on macOS and Windows; on Linux also install GTK WebKit). Logs from the desktop app go to
`~/Library/Logs/Subnetry.log` on macOS and `%LOCALAPPDATA%\Subnetry\Subnetry.log` on Windows (where a startup
problem also shows an error message).

### Platform notes

| | Wi-Fi scanning | Network scanning |
|---|---|---|
| **Windows** | `netsh wlan`. On Windows 11 it needs **Location** access (Settings › Privacy & security › Location). The parser expects English output. | `ping`, `arp -a` |
| **macOS** | `system_profiler`. On macOS 14+ SSIDs are hidden unless your terminal/Python has **Location Services** permission. BSSIDs are not exposed. | `ping`, `arp -an` |
| **Linux** | `nmcli` (NetworkManager) | `ping`, `ip neigh` |

None of the built-in tools need admin/root rights. The two optional external tools are:

| Tool | Install | Notes |
|---|---|---|
| **Speedtest.net CLI** (Speed Test) | macOS: `brew tap teamookla/speedtest`, `brew trust teamookla/speedtest` (newer Homebrew), then `brew install speedtest --force` · Windows: `winget install Ookla.Speedtest.CLI` · Linux: [speedtest.net/apps/cli](https://www.speedtest.net/apps/cli) | Use Ookla's official CLI, not the unrelated Python `speedtest-cli`. Subnetry tells them apart. Running a test accepts Ookla's EULA and privacy policy. |
| **Nmap** (Port Scanner) | Windows/macOS: [nmap.org/download](https://nmap.org/download.html) · macOS: `brew install nmap` · Linux: `sudo apt install nmap` | Works without admin (TCP connect scan). OS detection needs admin/root. |
| **Wireshark / tshark** (Traffic Analyzer) | [wireshark.org/download](https://www.wireshark.org/download.html). Windows: keep **Npcap** and **TShark** ticked. Linux: `sudo apt install tshark` | Capture permissions: on macOS run Wireshark's "Install ChmodBPF" package; on Linux `sudo usermod -aG wireshark $USER` and log in again. |

Subnetry detects both automatically and shows install instructions in the app if they're missing.

**Wi-Fi Monitor** uses `iw` or `nmcli` on Linux and `netsh` on Windows.

**DNSDumpster (optional, DNS Lookup tab):** create a free account at [dnsdumpster.com](https://dnsdumpster.com/), copy the
API key from your account page and paste it into the DNS Lookup tab (or set `DNSDUMPSTER_API_KEY`). The key is saved
in `~/Subnetry-Reports/.subnetry-settings.json`, never in the project folder. The API allows one request every
2 seconds and free accounts have a daily quota, so Subnetry spaces requests out and caches results for 10 minutes.

**macOS Wi-Fi names:** since macOS 14, Wi-Fi network names and access-point IDs are only shown to apps with
Location Services permission, and macOS won't keep that permission for Homebrew's Python. So on first use Subnetry
builds a tiny helper app, **Subnetry Wi-Fi Helper** (Swift source in `subnetry/macos_helper/`). It's compiled with
Apple's command-line tools (`xcode-select --install` if they're missing), ad-hoc signed, and stored in
`~/Library/Application Support/Subnetry/` (if your Python is an Intel build running under Rosetta, the compiler is still
run natively on Apple Silicon). Press **Allow location access** in the Wi-Fi Scanner, choose Allow when macOS
asks, and the names appear. You can review this any time under System Settings › Privacy & Security ›
Location Services › Subnetry Wi-Fi Helper.

**What the Traffic Analyzer can see:** on Wi-Fi and switched networks a computer sees its own traffic plus
broadcast/multicast from other devices. Seeing every device needs a mirror/SPAN port, a Wi-Fi adapter in monitor
mode, or a capture on the router.

## Health Check: quick and full scans

| | Quick scan | Full scan |
|---|---|---|
| Speed test (download, upload, ping, jitter, packet loss) | ✔ | ✔ |
| Wi-Fi scan: signal, security, band and channel congestion | ✔ | ✔ |
| Traceroute to google.com: the path out to the internet, where delay or loss starts | | ✔ |
| Network scan of every device, saved to a file | | ✔ |
| Port scan: the 1000 most common TCP ports on each device | | ✔ |
| Typical time | 30–40 s | 3–6 min |

- **Speed test:** Speedtest.net through Ookla's official CLI. Cloudflare's test is used only when the CLI isn't
  installed (the results say so and explain how to install it) or when a Speedtest.net run fails.
- **Port scan:** Nmap (`--top-ports 1000`) when it's installed; otherwise Subnetry's built-in scanner checks the same
  1000 ports (the list comes from Nmap's port-frequency table, see `scripts/build_topports.py`).

When a scan finishes you get:

- **A health score (0–100)**: each critical issue costs 25 points and each warning 10.
  Any critical issue caps the grade at "Fair".
- **How to improve your score**: the fixes worth the most points, each with the change to make and how many
  points it adds.
- **Recommendations**, sorted Critical → Warning → Info → Looks good. Each one says what was found, why it
  matters, and the exact change to make. Examples: switching the router to a less crowded channel, moving off
  2.4 GHz, upgrading WPA/TKIP or open Wi-Fi, disabling Telnet/FTP/RDP/VNC on devices, enabling HTTPS for the
  router admin page, and reviewing UPnP.
- **Exports**: an HTML report (prints neatly to PDF), JSON, and CSVs of recommendations, devices and Wi-Fi networks.
  **Full scans are saved automatically** to `~/Subnetry-Reports/`: the HTML and JSON report plus the device list
  (IP, name, MAC, vendor and open ports) and Wi-Fi list as CSV files. Change the folder with `--reports-dir`.

The rules live in `subnetry/tools/advisor.py`. Each rule is a small, plain function, so it's easy to tune the
thresholds or add new checks.

## How it works

```
subnetry/
  __main__.py        # launcher: `python -m subnetry`
  server.py          # FastAPI routes; long tasks stream Server-Sent Events
  system.py          # cross-platform command runner
  tools/
    netinfo.py       # interfaces, gateway, DNS, public IP
    speedtest.py     # engine picker + built-in Cloudflare test (latency/jitter, download, upload)
    ookla.py         # Speedtest.net via Ookla's official CLI (JSONL progress)
    netscan.py       # host discovery, ARP, reverse DNS, port scan
    wifiscan.py      # per-OS Wi-Fi parsers + channel analysis
    diagnose.py      # quick/full scan orchestration
    advisor.py       # rules that turn results into recommendations + score
    report.py        # HTML / JSON / CSV export and auto-save
    ipinfo.py        # public IP / ISP / geolocation lookups
    nmapscan.py      # Nmap runner, progress parsing, XML results
    wifimonitor.py   # live connection sampling, roam & sticky-client detection
    macos.py         # macOS Location permission + CoreWLAN fallbacks
    macos_helper.py  # builds/drives the "Subnetry Wi-Fi Helper" app (Swift source in subnetry/macos_helper/)
    dashboard.py     # remembered "last results" + live latency/Wi-Fi stream for the home screen
    traffic.py       # tshark capture + plain-English traffic analysis
    traceroute.py    # traceroute/tracert runner, parsers, hop names/ASNs (Team Cymru DNS) and findings
    subnetcalc.py    # subnet / CIDR maths (ipaddress), splitting and summarizing
    macvendor.py     # OUI vendor database (Nmap list or IEEE registry download)
    portref.py       # common-port reference data
    topports.py      # Nmap's 1000 most common TCP ports (generated by scripts/build_topports.py)
    dnsinfo.py       # DNS lookups (dnspython), record explanations, SPF/DMARC parsing
    dnsdumpster.py   # DNSDumpster API: a domain's known hosts/subdomains (rate-limited, cached)
  desktop_app.py     # native window (pywebview) and the --install-app launcher
  desktop/           # app icons (.icns / .ico / .png), built by scripts/build_icons.py
  static/            # index.html, styles.css, app.js + one script per tool (no build step)
tests/               # parser tests with sample OS output, speed-test & API tests
```

Some background on the techniques used:

- **Host discovery** combines three signals because many devices (phones especially) ignore ping.
  A TCP connection that is *refused* still proves a host is up, because it answered with a RST.
  Probing an address also makes your OS ARP for it, so any IP that ends up in the ARP table answered at layer 2.
- **Randomized MACs**: if the second-lowest bit of the first byte is set (the "locally administered" bit),
  the MAC was made up by the device for privacy, as modern phones and laptops do.
- **MAC vendors**: the first 24 bits of a MAC (the OUI) are assigned to a manufacturer by the IEEE. Some
  manufacturers buy smaller 28- or 36-bit blocks instead, so the longest matching prefix wins.
- **DNS lookups** ask for EDNS so large TXT answers fit in one UDP packet. A query that times out is reported as
  "couldn't load", never as "missing", so a slow resolver can't produce a false "No SPF record" warning.
- **Speed test**: several parallel HTTP streams fill the pipe. The first second is ignored (TCP slow start),
  and the result is the average of 250 ms samples after that.
- **Channel recommendations** score each candidate channel by the nearby networks that overlap it, weighted by
  signal strength. Your own access points and mesh nodes don't count against you. The candidates are:
  - **2.4 GHz:** 1, 6 and 11, the only channels that don't overlap each other.
  - **5 GHz:** channels that need no radar checks (non-DFS). Neighbours in the same 80 MHz block count half.
  - **6 GHz:** the preferred scanning channels (PSC) that Wi-Fi 6E/7 devices look at first.

  A switch is only recommended when it is meaningfully better than the current channel.

## Development

```bash
pip install -e ".[dev]"
pytest
```

### Adding a new tool

1. Write the logic in `subnetry/tools/<tool>.py`. Keep it free of web code so it is easy to test.
2. Add a route in `server.py`. Return JSON for quick results, or `sse(async_generator)` for a live stream.
3. Add a sidebar button and a `<section id="tab-<name>">` in `static/index.html`. Put its logic in a new
   `static/<name>.js`, included before `main.js`. Register `loaders.<name>` if the tab should load data when opened.
   Shared helpers (`api`, `stream`, `lineChart`, `recCard`, `tile`, …) live in `app.js`.

### Ideas for next tools

- Ping / traceroute with a latency graph
- Heat-map floor plan for the Wi-Fi survey
- DNS server benchmark
- Scan history with trends over time (compare reports)
- Scheduled scans
- Service banner grabbing and mDNS/SSDP device discovery
- A standalone installer (PyInstaller) that doesn't need Python

## Responsible use

Only scan or capture on networks you own or have permission to test. The network scanner and Nmap
integration refuse public (non-private) address ranges. By default the server only listens on `localhost`.
