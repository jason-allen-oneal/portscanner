# portscanner
Yet another port scanner for the security community

## Features
- Multiple scan types: SYN, ACK, FIN, NULL, TCP, UDP, XMAS
- Supports scanning domains, IPs, IP ranges, and CIDR
- Multithreaded for speed
- Output to file option
- Colorized terminal output
- .gitignore included for Python projects

## Requirements
- Python 3.6+
- [scapy](https://pypi.org/project/scapy/)
- [tabulate](https://pypi.org/project/tabulate/)
- [colorama](https://pypi.org/project/colorama/)

Install dependencies:
```bash
pip install scapy tabulate colorama
```

## Usage
**Note:** You must run as root (or with sudo) to send raw packets.

```bash
sudo python3 portscanner.py [options]
```

### Examples
```bash
sudo python3 portscanner.py -T 127.0.0.1
sudo python3 portscanner.py -T www.example.com -T 127.0.0.1 -p 80,443,22,21
sudo python3 portscanner.py -T 192.168.1.1-5 -p all
sudo python3 portscanner.py -T 10.0.0.0/24 -S
```

### Options
```
Usage: portscanner.py [options]
example: python3 portscanner.py -T 127.0.0.1
example: python3 portscanner.py -T www.example.com -T 127.0.0.1

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         Show all output
  -q, --quiet           Minimize output
  -t THREADS, --threads=THREADS
                        Number of worker threads to spawn
  -w TIMEOUT, --timeout=TIMEOUT
                        Maximum time to wait for a response (in seconds)
  -r RETRIES, --retries=RETRIES
                        Number of times to retry a probe before dropping it
  -O WRITE, --out=WRITE
                        File to which to write the program's output

  Scan Types:
    Select a type of scan to run. (Default is SYN)

    -A, --ack           Perform ACK scan.
    -F, --fin           Perform FIN scan.
    -N, --null          Perform NULL scan.
    -S, --syn           Perform SYN scan.
    -B, --tcp           Basic TCP scan.
    -U, --udp           Perform UDP scan.
    -X, --xmas          Perform XMAS scan.

  Target Information:
    Information about the target(s)

    -T TARGETS, --targets=TARGETS
                        *REQUIRED* The targets you would like to scan. Can be
                        a domain, IP address, range of IP addresses, or CIDR
                        range.
    -p PORTS, --ports=PORTS
                        Ports to scan. Can be "basic" (1-1024), "all"
                        (1-65536), or a comma-separated list of ports.
                        Defaults to "basic".
```

### Example Output
```
Port Scanner by Jason O'Neal
Please use responsibly.
[*] Preparing to scan 172.235.158.51
[*] Host is up. Beginning syn scan of 4 ports on 172.235.158.51
[$] Port 80: Open
[$] Port 21: Open
[$] Port 22: Open

[*] Scan complete.
[*] 1 closed ports.

[$] Open ports
|   Port | Service   |
|--------|-----------|
|     80 | http      |
|     21 | ftp       |
|     22 | ssh       |

[*] Scan completed in 2 seconds.
```

---

**.gitignore** is included to keep your repo clean from Python and output artifacts.
