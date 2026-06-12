#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║          RECON DASHBOARD  —  by K4ZM1                ║
║     All-in-one recon CLI for pentest engagements     ║
╚══════════════════════════════════════════════════════╝

Modules:
  1. DNS Enumeration       — A/AAAA/MX/NS/TXT/CNAME
  2. WHOIS Lookup          — Registrar, dates, contacts
  3. Subdomain Bruteforce  — Wordlist-based discovery
  4. Port Scan             — Top ports via socket
  5. HTTP Fingerprint      — Headers, server, tech stack
  6. IP Geolocation        — Country, ASN, org
  7. SPF/DMARC Check       — Email security posture
  8. Full Recon            — Run all modules, save report

Usage:
  python3 recon_dashboard.py
  python3 recon_dashboard.py -t example.com
  python3 recon_dashboard.py -t example.com -m full
  python3 recon_dashboard.py -t example.com -m ports --ports 80,443,8080
"""

import argparse
import socket
import ssl
import json
import sys
import os
import re
import time
import subprocess
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError
import http.client

# ── Colour helpers ──────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue/cyan
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

def c(color, text): return f"{color}{text}{RESET}"

# ── Target normalisation ─────────────────────────────────────────────────────
from urllib.parse import urlparse

def extract_host(target):
    """Return hostname (with www) from any URL/domain/IP string."""
    t = target.strip().rstrip("/")
    if not t.startswith(("http://","https://")):
        t = "https://" + t
    return urlparse(t).hostname or t

def extract_domain(target):
    """Return root domain — strips www. prefix for DNS/WHOIS/SPF work."""
    host = extract_host(target)
    if host.startswith("www."):
        host = host[4:]
    return host

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗             ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║             ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║             ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║             ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║  ███║             ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝             ║
║         {Y}A L L - I N - O N E   R E C O N{C}            ║
║                   {DIM}by K4ZM1.com{C}                   ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")

def section(title):
    print(f"\n{B}{'─'*56}{RESET}")
    print(f"{BOLD}{Y}  ▶  {title}{RESET}")
    print(f"{B}{'─'*56}{RESET}")

def ok(msg):   print(f"  {G}[+]{RESET} {msg}")
def info(msg): print(f"  {C}[*]{RESET} {msg}")
def warn(msg): print(f"  {Y}[!]{RESET} {msg}")
def err(msg):  print(f"  {R}[-]{RESET} {msg}")


# ── DNS Enumeration ─────────────────────────────────────────────────────────
def dns_enum(target, results=None):
    section("DNS Enumeration")
    import subprocess
    domain = extract_domain(target)
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    found = {}
    info(f"Target domain: {c(Y, domain)}")

    for rtype in record_types:
        try:
            # Try dig first (standard on Kali/Debian), fallback to nslookup
            try:
                cmd = ["dig", "+short", rtype, domain]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            except FileNotFoundError:
                cmd = ["nslookup", f"-type={rtype}", domain]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                lines = [l.strip() for l in out.stdout.splitlines()
                         if l.strip() and "Server:" not in l and "Address:" not in l
                         and "#" not in l and "Non-authoritative" not in l]

            if lines:
                ok(f"{c(M, rtype):20s} {' | '.join(lines[:3])}")
                found[rtype] = lines[:3]
            else:
                info(f"{c(DIM, rtype):20s} No records")
        except Exception as e:
            warn(f"{rtype} lookup failed: {e}")

    # Also try Python socket for A record
    try:
        ip = socket.gethostbyname(domain)
        ok(f"{'Resolved IP':20s} {c(G, ip)}")
        found["IP"] = ip
    except:
        pass

    if results is not None:
        results["dns"] = found
    return found


# ── WHOIS Lookup ─────────────────────────────────────────────────────────────
def whois_lookup(target, results=None):
    section("WHOIS Lookup")
    domain = extract_domain(target)
    try:
        import subprocess
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        raw = out.stdout

        fields = {
            "Registrar":         r"(?i)Registrar:\s*(.+)",
            "Created":           r"(?i)(Creation Date|Created):\s*(.+)",
            "Expires":           r"(?i)(Expiry Date|Expiration):\s*(.+)",
            "Updated":           r"(?i)Updated Date:\s*(.+)",
            "Name Servers":      r"(?i)Name Server:\s*(.+)",
            "Registrant Org":    r"(?i)Registrant Organization:\s*(.+)",
            "Registrant Email":  r"(?i)Registrant Email:\s*(.+)",
            "Status":            r"(?i)Domain Status:\s*(.+)",
        }

        parsed = {}
        for label, pattern in fields.items():
            matches = re.findall(pattern, raw)
            if matches:
                val = matches[0] if isinstance(matches[0], str) else matches[0][-1]
                val = val.strip()[:80]
                ok(f"{label:20s} {c(W, val)}")
                parsed[label] = val

        if not parsed:
            warn("WHOIS returned no structured data (may be rate-limited or privacy-protected)")
            print(f"{DIM}{raw[:500]}{RESET}")

        if results is not None:
            results["whois"] = parsed
        return parsed

    except FileNotFoundError:
        err("'whois' not installed. Run: sudo apt install whois")
    except Exception as e:
        err(f"WHOIS failed: {e}")
    return {}


# ── Subdomain Bruteforce ─────────────────────────────────────────────────────
DEFAULT_WORDLIST = [
    "www","mail","ftp","smtp","pop","ns1","ns2","webmail","vpn","api",
    "dev","staging","test","beta","admin","portal","cdn","static","app",
    "login","auth","secure","shop","blog","m","mobile","assets","img",
    "media","docs","help","support","remote","intranet","crm","erp","git",
    "gitlab","jenkins","jira","confluence","kibana","elastic","mysql","db",
    "phpmyadmin","cpanel","whm","email","autodiscover","autoconfig",
]

def subdomain_bruteforce(target, wordlist=None, results=None):
    section("Subdomain Bruteforce")
    domain = extract_domain(target)
    words = wordlist if wordlist else DEFAULT_WORDLIST
    found_subs = []

    info(f"Testing {len(words)} subdomains against {c(Y, domain)}")
    for word in words:
        sub = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            ok(f"{c(G, sub):40s} → {c(C, ip)}")
            found_subs.append({"subdomain": sub, "ip": ip})
        except socket.gaierror:
            pass
        except Exception:
            pass

    if not found_subs:
        warn("No subdomains resolved (domain may use wildcard DNS or have few subs)")
    else:
        info(f"Found {c(G, str(len(found_subs)))} subdomains")

    if results is not None:
        results["subdomains"] = found_subs
    return found_subs


# ── Port Scanner ─────────────────────────────────────────────────────────────
TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
             1723,3306,3389,5900,8080,8443,8888,9200,27017]

def port_scan(target, ports=None, results=None):
    section("Port Scan")
    host = extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host

    scan_ports = ports if ports else TOP_PORTS
    info(f"Scanning {c(Y, ip)} — {len(scan_ports)} ports  (timeout: 1s)")

    open_ports = []
    services = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
        110:"POP3",111:"RPC",135:"RPC",139:"NetBIOS",143:"IMAP",
        443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",1723:"PPTP",
        3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",
        6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",
        9200:"Elasticsearch",27017:"MongoDB",
    }

    for port in sorted(scan_ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                svc = services.get(port, "unknown")
                ok(f"Port {c(G, str(port)):12s} {c(M, 'OPEN'):10s} {c(C, svc)}")
                open_ports.append({"port": port, "service": svc})
        except:
            pass

    if not open_ports:
        warn("No open ports found in the scanned range")
    else:
        info(f"Found {c(G, str(len(open_ports)))} open ports")

    if results is not None:
        results["ports"] = open_ports
    return open_ports


# ── HTTP Fingerprint ──────────────────────────────────────────────────────────
def http_fingerprint(target, results=None):
    section("HTTP Fingerprint")

    urls = []
    t = extract_host(target)
    for scheme in ["https", "http"]:
        urls.append(f"{scheme}://{t}")

    headers_data = {}
    for url in urls:
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0 (ReconBot/1.0)"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urlopen(req, timeout=8, context=ctx)
            hdrs = dict(resp.headers)

            ok(f"{'URL':20s} {c(G, url)}")
            ok(f"{'Status':20s} {c(G, str(resp.status))}")

            interesting = [
                "Server","X-Powered-By","X-Generator","X-Frame-Options",
                "Content-Security-Policy","Strict-Transport-Security",
                "X-Content-Type-Options","X-XSS-Protection","Via",
                "CF-Ray","X-Varnish","X-Cache","Set-Cookie",
            ]
            missing_security = []
            security_headers = ["X-Frame-Options","Content-Security-Policy",
                                 "Strict-Transport-Security","X-Content-Type-Options"]

            for h in interesting:
                val = hdrs.get(h, "")
                if val:
                    color = R if h in security_headers else W
                    ok(f"{h:30s} {c(color, val[:80])}")
                    headers_data[h] = val[:80]

            for sh in security_headers:
                if sh not in hdrs:
                    warn(f"Missing security header: {c(R, sh)}")
                    missing_security.append(sh)

            headers_data["missing_security"] = missing_security
            headers_data["url"] = url
            headers_data["status"] = resp.status
            break

        except Exception as e:
            warn(f"{url} → {e}")

    if results is not None:
        results["http"] = headers_data
    return headers_data


# ── IP Geolocation ────────────────────────────────────────────────────────────
def ip_geo(target, results=None):
    section("IP Geolocation & ASN")
    host = extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host

    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = Request(url, headers={"User-Agent": "ReconBot/1.0"})
        raw = urlopen(req, timeout=8).read()
        data = json.loads(raw)

        fields = [
            ("IP",       data.get("ip","")),
            ("Country",  data.get("country_name","")),
            ("City",     data.get("city","")),
            ("Region",   data.get("region","")),
            ("ISP/Org",  data.get("org","")),
            ("ASN",      data.get("asn","")),
            ("Timezone", data.get("timezone","")),
            ("Latitude", str(data.get("latitude",""))),
            ("Longitude",str(data.get("longitude",""))),
        ]

        for label, val in fields:
            if val:
                ok(f"{label:15s} {c(W, val)}")

        if results is not None:
            results["geo"] = dict(fields)
        return dict(fields)

    except Exception as e:
        err(f"Geolocation failed: {e}")
        return {}


# ── SPF / DMARC Check ────────────────────────────────────────────────────────
def spf_dmarc_check(target, results=None):
    section("SPF / DMARC / DKIM Check")
    domain = extract_domain(target)

    checks = {}
    try:
        import subprocess

        def dig_txt(name):
            try:
                out = subprocess.run(["dig","+short","TXT", name],
                                     capture_output=True, text=True, timeout=5)
                return out.stdout
            except FileNotFoundError:
                out = subprocess.run(["nslookup","-type=TXT", name],
                                     capture_output=True, text=True, timeout=5)
                return out.stdout

        # SPF
        txt = dig_txt(domain)
        spf_match = re.search(r'(v=spf1[^\n"]+)', txt)
        if spf_match:
            spf = spf_match.group(1).strip()
            ok(f"{'SPF':10s} {c(G, spf[:100])}")
            checks["SPF"] = spf
            if "+all" in spf:
                warn(f"SPF uses {c(R, '+all')} — dangerous, allows any sender!")
            elif "~all" in spf:
                warn(f"SPF uses {c(Y, '~all')} — SoftFail, consider -all")
            elif "-all" in spf:
                ok(f"SPF policy is {c(G, '-all')} (strict)")
        else:
            warn(f"{'SPF':10s} {c(R, 'NOT FOUND')} — no SPF record")
            checks["SPF"] = None

        # DMARC
        dmarc_txt = dig_txt(f"_dmarc.{domain}")
        dmarc_match = re.search(r'(v=DMARC1[^\n"]+)', dmarc_txt)
        if dmarc_match:
            dmarc = dmarc_match.group(1).strip()
            ok(f"{'DMARC':10s} {c(G, dmarc[:100])}")
            checks["DMARC"] = dmarc
            if "p=none" in dmarc:
                warn(f"DMARC policy is {c(Y, 'p=none')} — monitoring only, no enforcement")
            elif "p=quarantine" in dmarc:
                ok(f"DMARC policy: {c(Y, 'quarantine')}")
            elif "p=reject" in dmarc:
                ok(f"DMARC policy: {c(G, 'reject')} (strict)")
        else:
            warn(f"{'DMARC':10s} {c(R, 'NOT FOUND')} — vulnerable to email spoofing")
            checks["DMARC"] = None

        # MTA-STS hint
        mta_txt = dig_txt(f"_mta-sts.{domain}")
        if "v=STSv1" in mta_txt:
            ok(f"{'MTA-STS':10s} {c(G, 'Present')}")
        else:
            info(f"{'MTA-STS':10s} Not configured")

    except FileNotFoundError:
        err("'nslookup' not available")
    except Exception as e:
        err(f"SPF/DMARC check failed: {e}")

    if results is not None:
        results["email_security"] = checks
    return checks


# ── Save Report ───────────────────────────────────────────────────────────────
def save_report(target, results):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean = extract_domain(target).replace("/","_")
    filename = f"recon_{clean}_{ts}.json"
    with open(filename, "w") as f:
        json.dump({"target": target, "timestamp": ts, "results": results}, f, indent=2)
    ok(f"Report saved → {c(G, filename)}")
    return filename


# ── Interactive Menu ──────────────────────────────────────────────────────────
def interactive_menu(target):
    while True:
        print(f"""
{C}  Target: {Y}{target}{RESET}

  {G}[1]{RESET} DNS Enumeration
  {G}[2]{RESET} WHOIS Lookup
  {G}[3]{RESET} Subdomain Bruteforce
  {G}[4]{RESET} Port Scan
  {G}[5]{RESET} HTTP Fingerprint
  {G}[6]{RESET} IP Geolocation
  {G}[7]{RESET} SPF / DMARC Check
  {G}[8]{RESET} Full Recon (all modules)
  {G}[t]{RESET} Change Target
  {G}[q]{RESET} Quit
""")
        choice = input(f"  {B}recon{RESET} ❯ ").strip().lower()

        results = {}
        if   choice == "1": dns_enum(target)
        elif choice == "2": whois_lookup(target)
        elif choice == "3": subdomain_bruteforce(target)
        elif choice == "4": port_scan(target)
        elif choice == "5": http_fingerprint(target)
        elif choice == "6": ip_geo(target)
        elif choice == "7": spf_dmarc_check(target)
        elif choice == "8":
            info(f"Starting full recon on {c(Y, target)} ...")
            dns_enum(target, results)
            whois_lookup(target, results)
            subdomain_bruteforce(target, results=results)
            port_scan(target, results=results)
            http_fingerprint(target, results)
            ip_geo(target, results)
            spf_dmarc_check(target, results)
            fname = save_report(target, results)
            section("Full Recon Complete")
            ok(f"JSON report: {c(G, fname)}")
        elif choice == "t":
            target = input(f"  New target: ").strip()
            if not target:
                warn("Target cannot be empty")
        elif choice == "q":
            print(f"\n{DIM}  K4ZM1 | K4ZM1{RESET}\n")
            sys.exit(0)
        else:
            warn("Invalid choice")


# ── CLI Entry ────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Recon Dashboard by K4ZM1",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t","--target",  help="Target domain/IP")
    parser.add_argument("-m","--module",  default="menu",
        choices=["menu","dns","whois","subdomains","ports","http","geo","spf","full"],
        help="Module to run (default: interactive menu)")
    parser.add_argument("--ports", help="Comma-separated port list for port scan")
    parser.add_argument("-w","--wordlist", help="Path to subdomain wordlist file")
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    target = args.target
    if not target:
        target = input(f"  {B}Enter target{RESET} (domain/IP) ❯ ").strip()
    if not target:
        err("No target specified. Exiting.")
        sys.exit(1)

    # Normalize
    target = target.rstrip("/")

    # Custom ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except:
            warn("Invalid port list, using default top ports")

    # Custom wordlist
    wordlist = None
    if args.wordlist and os.path.isfile(args.wordlist):
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]
        info(f"Loaded {len(wordlist)} words from {args.wordlist}")

    results = {}

    if args.module == "menu":
        interactive_menu(target)
    elif args.module == "dns":
        dns_enum(target, results)
    elif args.module == "whois":
        whois_lookup(target, results)
    elif args.module == "subdomains":
        subdomain_bruteforce(target, wordlist, results)
    elif args.module == "ports":
        port_scan(target, ports, results)
    elif args.module == "http":
        http_fingerprint(target, results)
    elif args.module == "geo":
        ip_geo(target, results)
    elif args.module == "spf":
        spf_dmarc_check(target, results)
    elif args.module == "full":
        info(f"Starting full recon on {c(Y, target)} ...")
        dns_enum(target, results)
        whois_lookup(target, results)
        subdomain_bruteforce(target, wordlist, results)
        port_scan(target, ports, results)
        http_fingerprint(target, results)
        ip_geo(target, results)
        spf_dmarc_check(target, results)
        fname = save_report(target, results)
        section("Full Recon Complete")
        ok(f"JSON report: {c(G, fname)}")

    print()

if __name__ == "__main__":
    main()
