import socket
import sys

def scan_ports(ip, ports):
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    print(f"Port {port} is open")
                else:
                    print(f"Port {port} is closed")
        except socket.gaierror:
            print("Hostname could not be resolved.")
            sys.exit()
        except socket.error:
            print("Couldn't connect to server.")
            sys.exit()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scanner.py <ip> <ports>")
        sys.exit()

    ip_address = sys.argv[1]
    port_list = sys.argv[2].split(',')
    ports_to_scan = [int(port) for port in port_list]

    scan_ports(ip_address, ports_to_scan)
