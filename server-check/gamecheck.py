#!/usr/bin/env python3
"""
gamecheck - find the game server you are connected to and test the link to it.

Run it WHILE you are in a server (e.g. Battlefield 4). It will:
  1. Find the game process and sniff which remote IP it is exchanging UDP/TCP traffic with.
  2. Run: local network (gateway) ping, internet baseline ping, server ping
     (loss / latency / jitter / spikes / loss bursts), TCP probe, MTU check,
     and a per-hop traceroute to see WHERE loss or latency starts.
  3. Print a verdict (your side / your ISP / the route / the server).

Pure Python 3.8+ standard library. Works on Windows, Linux and macOS.
Sniffing needs admin (Windows: "Run as administrator") or root (Linux/macOS).
Without it, pass the IP yourself:  python gamecheck.py --ip 1.2.3.4

Examples
  python gamecheck.py                      # auto-detect bf4.exe, 100 pings
  python gamecheck.py --count 300          # longer test (more reliable)
  python gamecheck.py --process bf4.exe --sniff 15
  python gamecheck.py --ip 203.0.113.10    # skip detection
"""
import argparse
import ipaddress
import json
import platform
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ----------------------------------------------------------------- helpers
def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, creationflags=NOWIN)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local
                    or a.is_reserved or a.is_unspecified) and ip != "255.255.255.255"
    except ValueError:
        return False


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def hdr(t):
    print("\n" + "=" * 70 + f"\n {t}\n" + "=" * 70)


# ------------------------------------------------------- 1. find the server
def game_pids(name):
    pids = set()
    if IS_WIN:
        out = run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"])
        for line in out.splitlines():
            p = [x.strip('"') for x in line.split('","')]
            if len(p) > 1 and p[0].strip('"').lower() == name.lower():
                pids.add(int(p[1]))
    else:
        for line in run(["pgrep", "-if", name]).split():
            if line.isdigit():
                pids.add(int(line))
    return pids


def process_sockets(pids):
    """Return (udp_local_ports, tcp_remote_list[(ip,port)]) owned by pids."""
    udp_ports, tcp_remote = set(), []
    try:
        import psutil  # optional
        for c in psutil.net_connections(kind="inet"):
            if c.pid in pids:
                if c.type == socket.SOCK_DGRAM and c.laddr:
                    udp_ports.add(c.laddr.port)
                elif c.raddr and c.status == "ESTABLISHED":
                    tcp_remote.append((c.raddr.ip, c.raddr.port))
        return udp_ports, tcp_remote
    except Exception:
        pass
    if IS_WIN:
        for line in run(["netstat", "-ano"]).splitlines():
            p = line.split()
            if len(p) >= 4 and p[-1].isdigit() and int(p[-1]) in pids:
                if p[0] == "UDP":
                    udp_ports.add(int(p[1].rsplit(":", 1)[1]))
                elif p[0] == "TCP" and len(p) >= 5 and p[3].upper() == "ESTABLISHED":
                    ip, port = p[2].rsplit(":", 1)
                    if is_public(ip):
                        tcp_remote.append((ip, int(port)))
    else:
        for line in run(["ss", "-H", "-tunap"]).splitlines():
            m = re.search(r"pid=(\d+)", line)
            if not m or int(m.group(1)) not in pids:
                continue
            p = line.split()
            loc, rem = p[4], p[5]
            if p[0].startswith("udp"):
                udp_ports.add(int(loc.rsplit(":", 1)[1]))
            elif p[1] == "ESTAB":
                ip, port = rem.rsplit(":", 1)
                if is_public(ip):
                    tcp_remote.append((ip, int(port)))
    return udp_ports, tcp_remote


def sniff(seconds, my_ip, udp_ports):
    """Count packets/bytes per remote public IP. Needs admin/root."""
    stats = {}  # ip -> [pkts, bytes, {remote_ports}]
    if IS_WIN:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((my_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        offset = 0
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        offset = 14
    s.settimeout(0.5)
    end = time.time() + seconds
    try:
        while time.time() < end:
            try:
                data = s.recv(65535)
            except socket.timeout:
                continue
            ip = data[offset:]
            if len(ip) < 28 or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 15) * 4
            proto = ip[9]
            if proto != 17:  # UDP only (game traffic)
                continue
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            if src == my_ip:
                remote, lport, rport = dst, sport, dport
            elif dst == my_ip:
                remote, lport, rport = src, dport, sport
            else:
                continue
            if not is_public(remote) or (udp_ports and lport not in udp_ports):
                continue
            e = stats.setdefault(remote, [0, 0, set()])
            e[0] += 1
            e[1] += len(ip)
            e[2].add(rport)
    finally:
        if IS_WIN:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        s.close()
    return stats


def detect_server(args):
    hdr("1) FINDING THE GAME SERVER")
    pids = game_pids(args.process)
    if not pids:
        print(f"  Process '{args.process}' not running. Start the game and join a server first")
        print("  (or use --ip, or --process <exe name>).")
        return None, [], []
    print(f"  Found {args.process}  PID(s): {sorted(pids)}")
    udp_ports, tcp_remote = process_sockets(pids)
    print(f"  Game UDP ports: {sorted(udp_ports) or 'unknown'}")
    if tcp_remote:
        print("  Game TCP connections (EA/Battlelog/backend, may include server):")
        for ip, port in sorted(set(tcp_remote)):
            print(f"     {ip}:{port}")
    try:
        print(f"  Sniffing game UDP traffic for {args.sniff}s ...")
        st = sniff(args.sniff, local_ip(), udp_ports)
    except (PermissionError, OSError, AttributeError) as e:
        print(f"  ! Could not sniff packets ({e}).")
        print("    Run as Administrator/root, or pass the server with --ip.")
        return None, [], tcp_remote
    if not st:
        print("  ! No public UDP traffic seen. Are you in a server (not the menu)?")
        return None, [], tcp_remote
    ranked = sorted(st.items(), key=lambda kv: kv[1][1], reverse=True)
    print("  Remote peers by traffic:")
    for ip, (pk, by, ports) in ranked[:5]:
        print(f"     {ip:<16} {pk:>6} pkts {by/1024:>8.1f} KiB  remote ports {sorted(ports)[:4]}")
    best = ranked[0][0]
    ports = sorted(ranked[0][1][2])
    return best, ports, tcp_remote


# -------------------------------------------------------------- 2. pinging
def ping_once(ip, size=None, df=False, timeout_ms=1000):
    """One ICMP echo via system ping. Returns rtt ms, None (lost) or 'frag' (needs fragmentation)."""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms)]
        if size:
            cmd += ["-l", str(size)]
        if df:
            cmd += ["-f"]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms)]
        if size:
            cmd += ["-s", str(size)]
        if df:
            cmd += ["-D"]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, timeout_ms // 1000))]
        if size:
            cmd += ["-s", str(size)]
        if df:
            cmd += ["-M", "do"]
    out = run(cmd + [ip], timeout=timeout_ms / 1000 + 5)
    for line in out.splitlines():
        if re.search(r"TTL=\d+", line, re.I) and "expired" not in line.lower():
            m = re.search(r"[=<]\s*([\d.,]+)\s*ms", line, re.I)
            if m:
                v = float(m.group(1).replace(",", "."))
                return 0.5 if "<" in line and v <= 1 else v
            return 1.0
    low = out.lower()
    if df and ("fragment" in low or "too long" in low or "message too long" in low or "frag needed" in low):
        return "frag"
    return None


def ping_series(ip, count, interval=0.25, progress=None):
    res = []
    for i in range(count):
        t0 = time.time()
        res.append(ping_once(ip))
        if progress and (i + 1) % 10 == 0:
            progress(i + 1, count)
        time.sleep(max(0, interval - (time.time() - t0)))
    return res


def analyze(res):
    ok = [r for r in res if isinstance(r, float)]
    n = len(res)
    d = {"sent": n, "received": len(ok), "loss_pct": 100.0 * (n - len(ok)) / n if n else 100.0}
    # longest consecutive loss burst
    burst = cur = 0
    for r in res:
        cur = cur + 1 if not isinstance(r, float) else 0
        burst = max(burst, cur)
    d["max_loss_burst"] = burst
    if ok:
        s = sorted(ok)
        d.update(min=s[0], avg=statistics.mean(ok), max=s[-1], median=statistics.median(ok),
                 p95=s[min(len(s) - 1, int(len(s) * 0.95))],
                 stdev=statistics.pstdev(ok) if len(ok) > 1 else 0.0)
        diffs = [abs(a - b) for a, b in zip(ok, ok[1:])]
        d["jitter"] = statistics.mean(diffs) if diffs else 0.0
        d["spikes"] = sum(1 for x in ok if x > d["median"] * 2 + 15)
    return d


def fmt(d):
    if d["received"] == 0:
        return f"100% loss ({d['sent']} sent) - no reply (ICMP may be blocked)"
    return (f"loss {d['loss_pct']:.1f}% ({d['sent'] - d['received']}/{d['sent']})  "
            f"min/avg/med/p95/max {d['min']:.0f}/{d['avg']:.0f}/{d['median']:.0f}/{d['p95']:.0f}/{d['max']:.0f} ms  "
            f"jitter {d['jitter']:.1f} ms  spikes {d['spikes']}  worst loss burst {d['max_loss_burst']}")


def get_gateway():
    if IS_WIN:
        for line in run(["route", "print", "-4", "0.0.0.0"]).splitlines():
            m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                return m.group(1)
    elif IS_MAC:
        m = re.search(r"gateway:\s*(\S+)", run(["route", "-n", "get", "default"]))
        return m.group(1) if m else None
    else:
        m = re.search(r"default via (\S+)", run(["ip", "route", "show", "default"]))
        return m.group(1) if m else None
    return None


def timed_series(label, ip, count, interval=0.25):
    print(f"\n  [{label}] {ip}  ({count} pings)")
    res = ping_series(ip, count, interval,
                      progress=lambda i, n: print(f"     ... {i}/{n}", end="\r", flush=True))
    d = analyze(res)
    print("     " + fmt(d) + " " * 10)
    return d, res


# ----------------------------------------------------------- other tests
def tcp_probe(ip, ports, tries=5):
    out = {}
    for port in ports:
        times = []
        for _ in range(tries):
            t0 = time.time()
            try:
                with socket.create_connection((ip, port), timeout=1.5):
                    times.append((time.time() - t0) * 1000)
            except OSError as e:
                if getattr(e, "errno", None) in (111, 10061):  # refused = host reachable
                    times.append((time.time() - t0) * 1000)
            time.sleep(0.2)
        if times:
            out[port] = (len(times), tries, statistics.mean(times))
    return out


def mtu_test(ip):
    """Largest non-fragmenting payload (typical 1472 = 1500 MTU)."""
    if isinstance(ping_once(ip, size=1472, df=True), float):
        return 1500
    lo, hi, best = 1000, 1472, None
    for _ in range(6):
        mid = (lo + hi) // 2
        r = ping_once(ip, size=mid, df=True)
        if isinstance(r, float):
            best, lo = mid, mid + 1
        elif r == "frag":
            hi = mid - 1
        else:
            return None
    return best + 28 if best else None


def traceroute(ip):
    if IS_WIN:
        out = run(["tracert", "-d", "-h", "30", "-w", "800", ip], timeout=120)
    else:
        out = run(["traceroute", "-n", "-m", "30", "-q", "1", "-w", "1", ip], timeout=90)
        if not out:
            out = run(["tracepath", "-n", ip], timeout=90)
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", m.group(2))
        hops.append((int(m.group(1)), ipm.group(1) if ipm else None))
    return hops


def hop_test(hops, count=12):
    results = {}

    def work(h, ip):
        results[h] = analyze([ping_once(ip, timeout_ms=800) for _ in range(count)])
    ts = [threading.Thread(target=work, args=(h, ip)) for h, ip in hops if ip]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return results


# -------------------------------------------------------------- main flow
def main():
    ap = argparse.ArgumentParser(description="Find your game server and test your connection to it.")
    ap.add_argument("--ip", help="server IP (skip auto-detection)")
    ap.add_argument("--process", default="bf4.exe" if IS_WIN else "bf4", help="game process name (default bf4.exe)")
    ap.add_argument("--sniff", type=int, default=8, help="seconds to sniff game traffic (default 8)")
    ap.add_argument("--count", type=int, default=100, help="pings to the server (default 100, ~30s)")
    ap.add_argument("--json", help="also save results to this JSON file")
    ap.add_argument("--no-trace", action="store_true", help="skip traceroute/per-hop test")
    args = ap.parse_args()

    print("gamecheck - game server connection tester")
    server, rports, tcp_remote = args.ip, [], []
    if not server:
        server, rports, tcp_remote = detect_server(args)
    if not server:
        if tcp_remote:
            print("\n  Using the busiest TCP peer is unreliable; re-run with --ip once you know the server.")
        sys.exit(1)

    hdr(f"SERVER: {server}")
    try:
        print(f"  Reverse DNS: {socket.gethostbyaddr(server)[0]}")
    except OSError:
        print("  Reverse DNS: (none)")
    if rports:
        print(f"  Game port(s) seen: {rports[:5]}")

    report = {"server": server}
    hdr("2) LOCAL NETWORK + INTERNET BASELINE")
    gw = get_gateway()
    gwd = None
    if gw:
        gwd, _ = timed_series("Router/gateway (Wi-Fi/LAN quality)", gw, 40, 0.2)
    else:
        print("  (could not detect gateway)")
    base = {}
    for name, ip in (("Cloudflare DNS", "1.1.1.1"), ("Google DNS", "8.8.8.8")):
        base[ip], _ = timed_series(f"Internet baseline: {name}", ip, 40, 0.2)

    hdr("3) PING TO THE GAME SERVER")
    sd, series = timed_series("Game server", server, args.count)
    report["server_ping"] = sd
    # time-slice view: is loss/latency steady or in bursts?
    if sd["received"]:
        chunk = max(10, len(series) // 5)
        print("\n  Stability over time (each block = consecutive pings):")
        for i in range(0, len(series), chunk):
            part = analyze(series[i:i + chunk])
            avg = f"{part['avg']:.0f}ms" if part["received"] else "  -  "
            bar = "#" * int(min(40, part["avg"] / 5)) if part["received"] else ""
            print(f"     {i+1:>4}-{min(i+chunk, len(series)):<4} avg {avg:>6}  loss {part['loss_pct']:>5.1f}%  {bar}")

    hdr("4) TCP REACHABILITY (works even if ICMP is blocked)")
    ports = sorted({p for i, p in tcp_remote if i == server})
    tp = tcp_probe(server, ports or [80, 443, 25200, 47200], tries=4)
    if tp:
        for p, (ok, n, avg) in tp.items():
            print(f"     port {p}: {ok}/{n} connects, avg {avg:.0f} ms")
    else:
        print("     no TCP port responded (normal for UDP-only game servers)")

    hdr("5) MTU / FRAGMENTATION")
    mtu = mtu_test(server)
    if mtu is None:
        print("     could not determine (ICMP blocked?)")
    else:
        print(f"     path MTU ~ {mtu}  " + ("(OK)" if mtu >= 1500 else "(below 1500: fragmentation may add lag/loss - check VPN/PPPoE)"))
    report["mtu"] = mtu

    hops, hopres = [], {}
    if not args.no_trace:
        hdr("6) ROUTE + PER-HOP LOSS (like MTR)")
        print("  tracing...", flush=True)
        hops = traceroute(server)
        if not hops:
            print("     traceroute unavailable")
        else:
            hopres = hop_test(hops)
            print(f"  {'hop':>3}  {'ip':<16} {'loss':>6} {'avg ms':>7} {'max ms':>7}")
            for h, ip in hops:
                if not ip:
                    print(f"  {h:>3}  {'*  (no reply)':<16}")
                    continue
                d = hopres.get(h)
                if d and d["received"]:
                    print(f"  {h:>3}  {ip:<16} {d['loss_pct']:>5.0f}% {d['avg']:>7.0f} {d['max']:>7.0f}")
                else:
                    print(f"  {h:>3}  {ip:<16} {'100%':>6}   (router ignores ping - usually harmless)")
            print("  Note: loss on ONE middle hop that does not continue to later hops is harmless")
            print("  (routers deprioritise ping). Loss that persists to the server is real.")

    # ------------------------------------------------------------ verdict
    hdr("VERDICT")
    issues, good = [], []
    gwl = gwd["loss_pct"] if gwd and gwd["sent"] else None
    base_ok = [b for b in base.values() if b["received"]]
    base_loss = max((b["loss_pct"] for b in base_ok), default=None)
    base_avg = min((b["avg"] for b in base_ok), default=None)

    if gwd and gwd["received"]:
        if gwl > 0 or gwd["jitter"] > 5 or gwd["avg"] > 10:
            issues.append(f"LOCAL network unstable (router loss {gwl:.1f}%, avg {gwd['avg']:.0f}ms, jitter "
                          f"{gwd['jitter']:.1f}ms). Use Ethernet instead of Wi-Fi, check for downloads/streams/other devices.")
        else:
            good.append("Local network to your router is clean.")
    if base_loss is not None:
        if base_loss > 0:
            issues.append(f"INTERNET baseline loss {base_loss:.1f}% to 1.1.1.1/8.8.8.8 - problem is on your line/ISP, not the game server.")
        else:
            good.append("Internet baseline has no packet loss.")

    if sd["received"] == 0:
        issues.append("Server never answered ICMP (it probably blocks ping). Use hop results + TCP results + in-game net graph (BF4 console: `PerfOverlay.DrawFps 1` / `PerfOverlay.DrawGraph 1`).")
    else:
        if sd["loss_pct"] >= 2:
            where = "your side/ISP" if (base_loss or 0) > 0 or (gwl or 0) > 0 else "the route or the server"
            issues.append(f"PACKET LOSS {sd['loss_pct']:.1f}% to server - likely {where}. This causes rubber-banding/'hit reg' issues.")
        elif sd["loss_pct"] > 0:
            issues.append(f"Minor packet loss {sd['loss_pct']:.1f}% - noticeable only if it repeats on re-test.")
        else:
            good.append("0% packet loss to the server.")
        if sd["max_loss_burst"] >= 3:
            issues.append(f"Loss comes in bursts (up to {sd['max_loss_burst']} in a row) - typical of Wi-Fi interference or ISP congestion.")
        if sd["jitter"] > 15 or sd["stdev"] > 25:
            issues.append(f"HIGH JITTER {sd['jitter']:.1f} ms (stdev {sd['stdev']:.0f}) - unstable latency, feels like lag spikes.")
        else:
            good.append(f"Jitter is low ({sd['jitter']:.1f} ms).")
        if sd["spikes"] > max(2, sd["received"] * 0.03):
            issues.append(f"{sd['spikes']} latency spikes (>2x median) during the test.")
        if sd["avg"] > 100:
            issues.append(f"High ping {sd['avg']:.0f} ms - server is far away; pick a closer server.")
        elif sd["avg"] > 60:
            good.append(f"Ping {sd['avg']:.0f} ms is playable but not great.")
        else:
            good.append(f"Ping {sd['avg']:.0f} ms is good.")
        if base_avg and sd["avg"] - base_avg > 80:
            issues.append("Server latency far above internet baseline: long route or overloaded server.")
    if mtu and mtu < 1500:
        issues.append(f"Path MTU {mtu} < 1500 (VPN/PPPoE?) - can fragment game packets.")

    for g in good:
        print("  [OK]  " + g)
    for i in issues:
        print("  [!!]  " + i)
    if not issues:
        print("\n  => Your connection to this server looks healthy.")
        print("     If you still lag: it may be server tick rate/overload, not your network.")
    print("\n  Tip: for rare spikes run longer:  --count 600 (about 3 minutes) while playing.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"server": server, "gateway": gwd, "baseline": base, "server_ping": sd,
                       "mtu": mtu, "hops": [{"hop": h, "ip": ip, **(hopres.get(h) or {})} for h, ip in hops],
                       "issues": issues}, f, indent=2, default=str)
        print(f"  Saved JSON: {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
