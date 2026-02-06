#!/usr/bin/env python3
"""
cidr_block_domains_full.py

FULL MERGED SCRIPT:
• Stylish colorful UI
• Manual CIDR or TXT input
• One request per block (/28 etc.)
• Print '<IP> - <x domains>' (IP green, count blue)
• Save ONLY domains to output file
• Ask for threads
• Auto-refresh cookies every 10 minutes
• Auto-reload cookies when resumed via tmux (SIGCONT)
"""

import ipaddress
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, Style, init
import signal

init(autoreset=True)

# ------------ Config ------------
COOKIES_FILE = "cookies.json"
USE_API_KEY = False
API_KEY = ""
DELAY = 0.15
TIMEOUT = 25
RETRIES = 2
COOKIE_REFRESH_MINUTES = 10
# ---------------------------------


# ===========================================================
#                    COOKIE MANAGER
# ===========================================================

class CookieManager:
    def __init__(self, filename):
        self.filename = filename
        self.cookies = None
        self.last_loaded = None
        self.reload_interval = timedelta(minutes=COOKIE_REFRESH_MINUTES)

    def load(self):
        """Force load cookies.json"""
        try:
            data = json.load(open(self.filename, "r"))
            jar = requests.cookies.RequestsCookieJar()

            for c in data:
                jar.set(c["name"], c["value"],
                        domain=c.get("domain", ""),
                        path=c.get("path", "/"))

            self.cookies = jar
            self.last_loaded = datetime.now()
            print(Fore.GREEN + f"[✔] Cookies loaded from {self.filename}")

        except Exception as e:
            print(Fore.RED + f"[!] Failed to load cookies: {e}")
            self.cookies = None

    def get(self):
        """Return cookies, refreshing every 10 minutes."""
        if (
            self.cookies is None or
            self.last_loaded is None or
            datetime.now() - self.last_loaded > self.reload_interval
        ):
            print(Fore.YELLOW + "[i] Refreshing cookies (10 minute timer)…")
            self.load()

        return self.cookies

    def force_reload(self):
        print(Fore.YELLOW + "[i] Reloading cookies after resume (SIGCONT)…")
        self.load()


cookie_manager = CookieManager(COOKIES_FILE)


# SIGCONT handler for tmux resume (fg)
def handle_resume(signum, frame):
    cookie_manager.force_reload()


signal.signal(signal.SIGCONT, handle_resume)


# ===========================================================
#                    DISPLAY BANNER
# ===========================================================

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


# ===========================================================
#                NETWORK HELPERS
# ===========================================================

def pick_ip(subnet):
    hosts = list(subnet.hosts())
    return str(hosts[0]) if hosts else str(subnet.network_address)


def request_block(ip, mask, session, headers):
    """Perform 1 API request per block."""
    url = f"https://securitytrails.com/api/public/app/api/vercel/ip/{ip}?mask={mask}"

    for attempt in range(RETRIES + 1):
        try:
            cookies = cookie_manager.get()
            r = session.post(url, headers=headers, cookies=cookies, timeout=TIMEOUT)

            # Retry on non-200
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
    return (
        Fore.GREEN + f"{ip}" +
        Fore.WHITE + " - " +
        Fore.BLUE + f"{count} domains"
    )


# ===========================================================
#                        MAIN
# ===========================================================

def main():
    banner()

    print(Fore.YELLOW + "Input method:")
    print(Fore.YELLOW + "1) Enter big CIDR manually")
    print(Fore.YELLOW + "2) Load from TXT file")

    choice = input(Fore.CYAN + "Choose (1/2): ").strip()
    cidrs = []

    if choice == "1":
        cidrs = [input(Fore.CYAN + "Enter CIDR: ").strip()]
    else:
        path = input(Fore.CYAN + "Enter file path: ").strip()
        if not Path(path).exists():
            print(Fore.RED + "[!] File not found")
            return
        cidrs = [l.strip() for l in open(path) if l.strip()]

    small_prefix = int(input(Fore.CYAN + "Enter small block size (e.g., 28): ").strip())
    threads = int(input(Fore.CYAN + "Enter number of threads: ").strip())

    out_name = input(Fore.CYAN + "Enter output TXT filename: ").strip()
    if not out_name.endswith(".txt"):
        out_name += ".txt"

    out_file = Path(out_name)
    all_domains = set()

    session = requests.Session()
    headers = {"User-Agent": "cidr_domain_scanner/3.0"}

    if USE_API_KEY:
        headers["Authorization"] = API_KEY

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
            return request_block(rep_ip, small_prefix, session, headers)

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(worker, s) for s in subnets]

            for fut in as_completed(futures):
                mapping = fut.result()

                for ipfield, doms in mapping.items():
                    print(ip_line(ipfield, len(doms)))
                    for d in doms:
                        all_domains.add(d)

    # Write ONLY domains to file
    with open(out_file, "w") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")

    print(
        Fore.GREEN +
        f"\n[✔] Done. Total domains: {len(all_domains)}. Saved to: {out_file}"
    )


if __name__ == "__main__":
    main()








