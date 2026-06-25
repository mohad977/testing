#!/usr/bin/env python3
import socket
import argparse
import concurrent.futures
import ipaddress
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

# ── Helpers ────────────────────────────────────────────────────────────────────

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        hostname = resolve_ip(ip)
    except socket.gaierror as e:
        print(f"[ERROR] Cannot resolve '{target}': {e}")
        return None, None
    return hostname, ip

def parse_ports(port_arg):
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def divider(n=54):
    print("─" * n)

# ── Port scanning ──────────────────────────────────────────────────────────────

def scan_port(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return port, True, service
    except (ConnectionRefusedError, OSError, TimeoutError):
        return port, False, None

def scan_ports(ip, ports, timeout, workers):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
    return sorted(open_ports)

# ── Host discovery ─────────────────────────────────────────────────────────────

def is_host_alive(ip, timeout):
    probe_ports = [80, 443, 22, 445, 23, 8080, 3389, 53, 21, 25]
    for port in probe_ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (ConnectionRefusedError, OSError, TimeoutError):
            pass
    return False

def discover_hosts(subnet, timeout, workers):
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    total = len(hosts)
    print(f"  [*] Probing {total} host(s) in {subnet} ...")
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in hosts}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            done += 1
            if future.result():
                live.append(ip)
            # progress every 10%
            if done % max(1, total // 10) == 0:
                pct = int(done / total * 100)
                print(f"  [*] Progress: {pct}% ({done}/{total})  live so far: {len(live)}", flush=True)
    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))

# ── Scan modes ─────────────────────────────────────────────────────────────────

def run_single(target, ports, timeout, workers):
    hostname, ip = resolve_host(target)
    if ip is None:
        return
    print(f"  Hostname : {hostname}")
    print(f"  IP       : {ip}")
    print(f"  Ports    : {len(ports)}")
    divider()
    open_ports = scan_ports(ip, ports, timeout, workers)
    _print_ports(open_ports)
    print(f"\n  Result: {len(open_ports)} open port(s) found.")

def run_network(subnet, ports, timeout, workers):
    local_ip = get_local_ip()
    print(f"  Local IP : {local_ip}")
    print(f"  Target   : {subnet}")
    print(f"  Ports    : {len(ports)} per host")
    divider()

    live_hosts = discover_hosts(subnet, timeout, workers)

    if not live_hosts:
        print("\n  No live hosts found.")
        return

    print(f"\n  [+] {len(live_hosts)} live host(s) found. Scanning ports...\n")
    divider()

    total_open = 0
    for ip in live_hosts:
        hostname = resolve_ip(ip)
        open_ports = scan_ports(ip, ports, timeout, workers)
        total_open += len(open_ports)
        tag = "  ← this machine" if ip == local_ip else ""
        print(f"\n  Host : {ip}  ({hostname}){tag}")
        _print_ports(open_ports)

    print(f"\n  Result: {len(live_hosts)} host(s) found, {total_open} open port(s) total.")

def _print_ports(open_ports):
    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<10} SERVICE")
        print(f"  {'─'*34}")
        for port, service in open_ports:
            print(f"  {port:<8} {'open':<10} {service}")
    else:
        print("  No open ports.")

# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network scanner — single host, local network, or any subnet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single host:
    python3 netscanner.py google.com
    python3 netscanner.py 192.168.1.1 -p 22,80,443

  Local network (auto-detect):
    python3 netscanner.py --local

  Any subnet:
    python3 netscanner.py --network 192.168.0.0/24
    python3 netscanner.py --network 10.0.0.0/16
    python3 netscanner.py --network 172.16.0.0/20 -p 22,80,443,3389
        """
    )
    parser.add_argument("target", nargs="?", help="Hostname or IP to scan")
    parser.add_argument("--local", action="store_true", help="Scan local /24 subnet (auto-detected)")
    parser.add_argument("--network", metavar="CIDR", help="Scan any subnet, e.g. 10.0.0.0/16")
    parser.add_argument("-p", "--ports", default=None,
                        help="Ports: 22,80,443 or 1-1024. Default: 16 common ports")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Timeout per connection in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="Parallel threads (default: 200)")
    args = parser.parse_args()

    if not args.local and not args.network and not args.target:
        parser.print_help()
        return

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    print(f"\n{'═'*54}")
    print(f"  Network Scanner")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    divider()

    if args.local:
        local_ip = get_local_ip()
        subnet = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        run_network(subnet, ports, args.timeout, args.workers)

    elif args.network:
        try:
            subnet = str(ipaddress.IPv4Network(args.network, strict=False))
        except ValueError as e:
            print(f"[ERROR] Invalid subnet '{args.network}': {e}")
            return
        host_count = ipaddress.IPv4Network(subnet).num_addresses - 2
        if host_count > 65534:
            print(f"[WARN] Subnet has {host_count} hosts — this may take a long time.")
            confirm = input("  Continue? [y/N]: ").strip().lower()
            if confirm != "y":
                print("  Aborted.")
                return
        run_network(subnet, ports, args.timeout, args.workers)

    else:
        run_single(args.target, ports, args.timeout, args.workers)

    print(f"\n  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*54}\n")

if __name__ == "__main__":
    main()
