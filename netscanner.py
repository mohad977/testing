#!/usr/bin/env python3
import socket
import argparse
import concurrent.futures
import ipaddress
import struct
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

# ── Host info ──────────────────────────────────────────────────────────────────

def get_local_ip():
    """Get this machine's outbound IP (no packets actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def get_local_subnet():
    """Return the /24 subnet of the local machine (e.g. 192.168.1.0/24)."""
    local_ip = get_local_ip()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(network)

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ip
    except socket.gaierror as e:
        print(f"[ERROR] Cannot resolve '{target}': {e}")
        return None, None
    return hostname, ip

# ── Port scanning ──────────────────────────────────────────────────────────────

def scan_port(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return port, True, service
    except (ConnectionRefusedError, OSError, TimeoutError):
        return port, False, None

def scan_ports(ip, ports, timeout=1.0, workers=100):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
    return sorted(open_ports)

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

# ── Host discovery ─────────────────────────────────────────────────────────────

def is_host_alive(ip, timeout=0.5):
    """Probe a handful of common ports to check if a host is up."""
    probe_ports = [80, 443, 22, 445, 139, 8080, 3389]
    for port in probe_ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (ConnectionRefusedError, OSError, TimeoutError):
            pass
    return False

def discover_hosts(subnet, timeout=0.5, workers=200):
    """Return list of live IPs in the given subnet."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(is_host_alive, ip, timeout): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                live.append(ip)
    return sorted(live, key=lambda x: ipaddress.IPv4Address(x))

# ── Output helpers ─────────────────────────────────────────────────────────────

def divider(n=50):
    print("=" * n)

def print_host_ports(ip, ports, timeout, workers):
    hostname, _ = resolve_host(ip)
    open_ports = scan_ports(ip, ports, timeout=timeout, workers=workers)
    print(f"\n  Host     : {ip}  ({hostname})")
    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<10} SERVICE")
        print(f"  {'-'*34}")
        for port, service in open_ports:
            print(f"  {port:<8} {'open':<10} {service}")
    else:
        print("  No open ports found.")

# ── Modes ──────────────────────────────────────────────────────────────────────

def run_single(args, ports):
    hostname, ip = resolve_host(args.target)
    if ip is None:
        return
    print(f"  Hostname : {hostname}")
    print(f"  IP       : {ip}")
    print(f"  Scanning : {len(ports)} port(s)")
    divider()
    open_ports = scan_ports(ip, ports, timeout=args.timeout, workers=args.workers)
    if open_ports:
        print(f"\n  {'PORT':<8} {'STATE':<10} SERVICE")
        print(f"  {'-'*34}")
        for port, service in open_ports:
            print(f"  {port:<8} {'open':<10} {service}")
    else:
        print("\n  No open ports found.")
    print(f"\n  Scan complete — {len(open_ports)} open port(s) found.")

def run_local(args, ports):
    subnet = args.subnet if args.subnet else get_local_subnet()
    local_ip = get_local_ip()
    print(f"  Local IP : {local_ip}")
    print(f"  Subnet   : {subnet}")
    print(f"  Ports    : {len(ports)} port(s) per host")
    divider()
    print(f"\n  [*] Discovering live hosts in {subnet} ...")
    live_hosts = discover_hosts(subnet, timeout=args.timeout)
    if not live_hosts:
        print("  No live hosts found.")
        return
    print(f"  [+] Found {len(live_hosts)} live host(s). Scanning ports ...\n")
    divider()
    total_open = 0
    for ip in live_hosts:
        hostname, _ = resolve_host(ip)
        open_ports = scan_ports(ip, ports, timeout=args.timeout, workers=args.workers)
        total_open += len(open_ports)
        tag = " <-- this machine" if ip == local_ip else ""
        print(f"\n  Host : {ip}  ({hostname}){tag}")
        if open_ports:
            print(f"  {'PORT':<8} {'STATE':<10} SERVICE")
            print(f"  {'-'*34}")
            for port, service in open_ports:
                print(f"  {port:<8} {'open':<10} {service}")
        else:
            print("  No open ports found.")
    print(f"\n  Scan complete — {len(live_hosts)} host(s), {total_open} open port(s) total.")

# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network scanner — single host or full local subnet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan local network (auto-detect subnet):
    python3 netscanner.py --local

  Scan a specific subnet:
    python3 netscanner.py --local --subnet 10.0.0.0/24

  Scan a single host:
    python3 netscanner.py google.com

  Scan specific ports:
    python3 netscanner.py 192.168.1.1 -p 22,80,443
    python3 netscanner.py --local -p 1-1024
        """
    )
    parser.add_argument("target", nargs="?", help="Hostname or IP to scan (omit with --local)")
    parser.add_argument("--local", action="store_true", help="Scan the local network subnet")
    parser.add_argument("--subnet", default=None, help="Subnet to scan, e.g. 192.168.1.0/24 (used with --local)")
    parser.add_argument("-p", "--ports", default=None,
                        help="Ports: e.g. 22,80,443 or 1-1024. Default: common ports")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Parallel threads (default: 100)")
    args = parser.parse_args()

    if not args.local and not args.target:
        parser.print_help()
        return

    print(f"\n{'='*50}")
    print(f"  Network Scanner")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    divider()

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    if args.local:
        run_local(args, ports)
    else:
        run_single(args, ports)

    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
