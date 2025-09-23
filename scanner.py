import socket
import sys

def scan_ports(target, ports):
    try:
        ip = socket.gethostbyname(target)
        print(f"Scanning target: {target} ({ip})")
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    print(f"Port {port} is open")
                else:
                    # To avoid spamming closed ports on large ranges,
                    # I will comment this out. The user can re-enable if they want.
                    # print(f"Port {port} is closed")
                    pass
        except socket.error:
            print("Couldn't connect to server.")
            sys.exit()

def parse_ports(port_string):
    ports = set()
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            try:
                start = int(start)
                end = int(end)
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"Invalid port range: {part}")
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"Invalid port: {part}")
                continue
    return sorted(list(ports))

if __name__ == "__main__":
    banner = """
--------------------
|    IP SCANNER    |
--------------------
"""
    credit = "by farrosfr"
    disclaimer = "\nDisclaimer: educational purpose and ethical use only\n"

    print(banner)
    print(credit)
    print(disclaimer)


    if len(sys.argv) != 3:
        print("Usage: python scanner.py <ip_or_domain> <ports>")
        print("Ports can be a single port, a comma-separated list, or a range (e.g., 80, 81-90).")
        sys.exit()

    target = sys.argv[1]
    port_string = sys.argv[2]
    ports_to_scan = parse_ports(port_string)

    if not ports_to_scan:
        print("No valid ports to scan.")
        sys.exit()

    scan_ports(target, ports_to_scan)
