#!/usr/bin/env python3
"""
cidr_block_domains_clean.py

• Split large CIDR → smaller blocks (e.g. /28)
• One API request per block
• Parse each IP inside block and count domains
• Print IP - X domains (IP green, number blue)
• Save ONLY domains to output TXT file
• Ask user for thread count
• Colorful interface
"""

import ipaddress
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, Style, init

init(autoreset=True)

# ------------ Config ------------
COOKIES_FILE = "cookies.json"
USE_API_KEY = False
API_KEY = ""
DELAY = 0.15
TIMEOUT = 25
RETRIES = 2
# ---------------------------------

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
 ██████╗ ██╗██████╗ ██████╗     ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗
██╔════╝ ██║██╔══██╗██╔══██╗    ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝
██║  ███╗██║██████╔╝██████╔╝    ██║  ██║██║     ██║   ██║██║     █████╔╝ 
██║   ██║██║██╔══██╗██╔═══╝     ██║  ██║██║     ██║   ██║██║     ██╔═██╗ 
╚██████╔╝██║██║  ██║██║         ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗
 ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝         ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝

          CIDR → Blocks → One Request → Domains Per IP
    """)

def load_cookies(path):
    if not Path(path).exists():
        return None
    try:
        data = json.load(open(path, "r"))
        jar = requests.cookies.RequestsCookieJar()
        for c in data:
            jar.set(c["name"], c["value"], domain=c.get("domain",""), path=c.get("path","/"))
        print(Fore.GREEN + "[✔] Loaded cookies.json")
        return jar
    except:
        print(Fore.RED + "[!] Failed loading cookies.json")
        return None

def pick_ip(subnet):
    hosts = list(subnet.hosts())
    return str(hosts[0]) if hosts else str(subnet.network_address)

def request_block(ip, mask, session, headers, cookies):
    url = f"https://securitytrails.com/api/public/app/api/vercel/ip/{ip}?mask={mask}"

    for attempt in range(RETRIES + 1):
        try:
            r = session.post(url, headers=headers, cookies=cookies, timeout=TIMEOUT)
            if r.status_code != 200:
                if attempt < RETRIES:
                    time.sleep(0.5)
                    continue
                return {}
            data = r.json()
            rows = data.get("result", {}).get("rows", [])
            mapping = {}
            for row in rows:
                ipfield = row.get("ip")
                hosts = row.get("hostnames", [])
                cleaned = [h.strip() for h in hosts if isinstance(h, str) and h.strip()]
                mapping[ipfield] = cleaned
            return mapping
        except:
            if attempt < RETRIES:
                time.sleep(0.5)
                continue
            return {}

    return {}

def ip_line(ip, count):
    """Return styled console line."""
    return (
        Fore.GREEN + f"{ip}" +
        Fore.WHITE + " - " +
        Fore.RED + f"{count} domains"
    )


def main():
    banner()

    print(Fore.YELLOW + "Input method:")
    print(Fore.YELLOW + "1) Enter big CIDR manually")
    print(Fore.YELLOW + "2) Load from TXT file")

    choice = input(Fore.CYAN + "Choose (1/2): ").strip()

    cidrs = []
    if choice == "1":
        c = input(Fore.CYAN + "Enter CIDR: ").strip()
        cidrs = [c]
    else:
        p = input(Fore.CYAN + "Enter file path: ").strip()
        if not Path(p).exists():
            print(Fore.RED + "[!] File not found")
            return
        cidrs = [l.strip() for l in open(p) if l.strip()]

    small_prefix = int(input(Fore.CYAN + "Enter small block size (e.g., 28): ").strip())
    threads = int(input(Fore.CYAN + "Enter number of threads: ").strip())

    out_name = input(Fore.CYAN + "Enter output TXT filename: ").strip()
    if not out_name.endswith(".txt"):
        out_name += ".txt"
    out_file = Path(out_name)

    session = requests.Session()
    headers = {"User-Agent": "cidr_domain_scanner/2.0"}

    cookies = None
    if USE_API_KEY:
        headers["Authorization"] = API_KEY
    else:
        cookies = load_cookies(COOKIES_FILE)

    all_domains = set()

    for big in cidrs:
        try:
            net = ipaddress.ip_network(big, strict=False)
        except:
            print(Fore.RED + f"[!] Invalid CIDR {big}")
            continue

        subnets = list(net.subnets(new_prefix=small_prefix))
        print(Fore.MAGENTA + f"\nProcessing {len(subnets)} blocks from {big}\n")

        def worker(subnet):
            rep_ip = pick_ip(subnet)
            time.sleep(DELAY)
            return request_block(rep_ip, small_prefix, session, headers, cookies)

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(worker, s) for s in subnets]

            for fut in as_completed(futures):
                mapping = fut.result()
                for ipfield, doms in mapping.items():
                    # Printing formatted IP - X domains
                    print(ip_line(ipfield, len(doms)))
                    # Only saving domains (not IPs)
                    for d in doms:
                        all_domains.add(d)

    # Save ONLY domains
    with open(out_file, "w") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")

    print(
        Fore.GREEN +
        f"\n[✔] Done. Total domains: {len(all_domains)}. Saved to: {out_file}"
    )

if __name__ == "__main__":
    main()
