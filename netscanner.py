#!/usr/bin/env python3
import socket
import argparse
import concurrent.futures
from datetime import datetime

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = target
    except socket.gaierror as e:
        print(f"[ERROR] Cannot resolve '{target}': {e}")
        return None, None
    return hostname, ip

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

def main():
    parser = argparse.ArgumentParser(description="Small network scanner — hostname, IP, and open ports")
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default=None,
                        help="Ports to scan (e.g. 22,80,443 or 1-1024). Default: common ports")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Parallel threads (default: 100)")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Network Scanner")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    hostname, ip = resolve_host(args.target)
    if ip is None:
        return

    print(f"  Hostname : {hostname}")
    print(f"  IP       : {ip}")

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    print(f"  Scanning : {len(ports)} port(s)")
    print(f"{'='*50}\n")

    open_ports = scan_ports(ip, ports, timeout=args.timeout, workers=args.workers)

    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
        print(f"  {'-'*35}")
        for port, service in open_ports:
            print(f"  {port:<8} {'open':<10} {service}")
    else:
        print("  No open ports found.")

    print(f"\n{'='*50}")
    print(f"  Scan complete. {len(open_ports)} open port(s) found.")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    main()
