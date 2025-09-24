# IP Scanner

A simple and fast multithreaded port scanner written in Python. This tool allows you to scan for open ports on a target IP address or domain.

## Features

*   Scans a range of ports or specific ports (e.g., 80, 443, 1024-2048).
*   Uses multithreading for faster scanning.
*   Resolves hostnames to IP addresses.
*   Clean and easy-to-read output.

## Usage

To use the scanner, run the `scanner.py` script from your terminal with the required arguments.

### Arguments

*   `target`: The IP address or domain to scan.
*   `-p, --ports`: The ports you want to scan. You can specify single ports, ranges, or a combination.
    *   Example: `80`
    *   Example: `1-1024`
    *   Example: `22,80,443,1000-2000`
*   `-t, --threads`: The number of threads to use for scanning. The default is 50. More threads can result in faster scanning but may also be less reliable or trigger network security measures.

### Example

```bash
python scanner.py 192.168.1.1 -p 1-1024 -t 100
```

This command will scan the IP address `192.168.1.1` for open ports in the range of 1 to 1024, using 100 threads.

## Disclaimer

This tool is intended for educational purposes and for use in ethical security testing scenarios only. By using this software, you agree that you will not use it for any malicious or illegal activities. The author is not responsible for any misuse of this tool.
