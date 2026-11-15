# gamecheck

Finds the game server you're connected to and tests your link to it
(packet loss, latency, jitter, spikes, MTU, route/per-hop loss, router + internet baseline).
Python 3.8+, no dependencies. Windows / Linux / macOS.

## Use (Battlefield 4 example)
1. Join a server in BF4 and stay in the match (alt-tab out).
2. Open a terminal **as Administrator** (Windows) or with `sudo` (Linux/macOS):

       python gamecheck.py

   It detects `bf4.exe`, sniffs its UDP traffic for a few seconds, picks the server IP, then tests it.

Options: `--ip 1.2.3.4` (skip detection, no admin needed), `--count 300` (longer test),
`--process name.exe` (other games), `--sniff 15`, `--no-trace`, `--json out.json`, `--html report.html` (default `gamecheck_report.html`, opens automatically), `--no-html`.

## What the verdict tells you
- Router loss/jitter -> your Wi-Fi/LAN. Use Ethernet.
- Loss to 1.1.1.1/8.8.8.8 too -> your ISP/line.
- Clean baseline but loss to server -> route or server problem.
- Servers often block ping; then rely on the per-hop and TCP results.
