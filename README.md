# portscanner
Yet another port scanner for the security communuity

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
