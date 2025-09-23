import socket
import sys
import argparse
import threading
from queue import Queue

# A lock to ensure thread-safe printing
print_lock = threading.Lock()

def scan_port(ip, port, open_ports):
    """Scans a single port and appends it to the list if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) # Lower timeout for faster scanning
            if s.connect_ex((ip, port)) == 0:
                with print_lock:
                    print(f"Port {port} is open")
                    open_ports.append(port)
    except socket.error:
        # This can happen if the host is down or firewall blocks connection
        # We can ignore this for a single port scan to avoid stopping the whole process
        pass

def thread_worker(q, ip, open_ports):
    """Worker thread function to pull ports from the queue and scan them."""
    while not q.empty():
        port = q.get()
        scan_port(ip, port, open_ports)
        q.task_done()

def scan_ports(target, ports, num_threads):
    """Sets up the multithreaded port scanning."""
    try:
        ip = socket.gethostbyname(target)
        print(f"Scanning target: {target} ({ip}) with {num_threads} threads.")
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

    open_ports = []
    port_queue = Queue()
    for port in ports:
        port_queue.put(port)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=thread_worker, args=(port_queue, ip, open_ports))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete their work
    for thread in threads:
        thread.join()

    if not open_ports:
        print("\nNo open ports found.")
    else:
        # Sort the list for a clean output
        open_ports.sort()
        print(f"\nFinished scan. Found {len(open_ports)} open port(s): {open_ports}")

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
  .__                                                                    
  |__|_____             ______ ____ _____    ____   ____   ___________   
  |  \____ \   ______  /  ___// ___\\__  \  /    \ /    \_/ __ \_  __ \  
  |  |  |_> > /_____/  \___ \\  \___ / __ \|   |  \   |  \  ___/|  | \/  
  |__|   __/          /____  >\___  >____  /___|  /___|  /\___  >__|     
  |__|                  \/     \/     \/     \/     \/     \/            

"""
    credit = "by farrosfr"
    disclaimer = "[!] DISCLAIMER: For educational purpose and ethical use only."

    parser = argparse.ArgumentParser(
        description=f"{banner}\n{credit}\n\n{disclaimer}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python scanner.py 192.168.1.1 -p 1-1024 -t 100"
    )
    parser.add_argument("target", help="The IP address or domain to scan.")
    parser.add_argument("-p", "--ports", dest="port_string", required=True, help="Ports to scan (e.g., 80, 81-90, 1-1024).")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use for scanning. Default is 50.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    ports_to_scan = parse_ports(args.port_string)

    if not ports_to_scan:
        print("No valid ports to scan.")
        sys.exit()

    scan_ports(args.target, ports_to_scan, args.threads)
