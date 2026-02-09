#!/usr/bin/env python3

import os
import socket
import ssl
import json
import shutil
import datetime
import subprocess
from urllib.parse import urlparse, urljoin
import requests

from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table
from rich import box

console = Console()

TIMEOUT = 10
USER_AGENT = "SafeReconFramework/3.0"

# ================= UI =================

def banner():
    console.print(Panel("""
 ███████╗ █████╗ ███████╗███████╗
 ██╔════╝██╔══██╗██╔════╝██╔════╝
 █████╗  ███████║███████╗█████╗
 ██╔══╝  ██╔══██║╚════██║██╔══╝
 ██║     ██║  ██║███████║███████╗
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
        SAFE RECON FRAMEWORK
    """, style="bold green", box=box.DOUBLE))

def menu():
    table = Table(title="SCAN LEVEL", box=box.ROUNDED)
    table.add_column("Option", justify="center", style="cyan")
    table.add_column("Mode", style="green")

    table.add_row("1", "Passive Scan")
    table.add_row("2", "Extended Scan")
    table.add_row("3", "Active Scan (nmap)")
    table.add_row("4", "Exit")

    console.print(table)

# ================= CORE =================

def normalize(target):
    if not target.startswith("http"):
        return "https://" + target
    return target

def resolve_dns(host):
    try:
        return socket.gethostbyname_ex(host)
    except Exception as e:
        return {"error": str(e)}

def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT,
                         headers={"User-Agent": USER_AGENT})
        return {
            "status": r.status_code,
            "final_url": r.url,
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {"error": str(e)}

def tls_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        return {
            "issuer": cert.get("issuer"),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter")
        }
    except Exception as e:
        return {"error": str(e)}

def check_path(base, path):
    try:
        return fetch(urljoin(base, path))
    except Exception as e:
        return {"error": str(e)}

def simple_dirs(base):
    paths = ["/admin","/login","/.git","/.env","/backup","/api"]
    results = {}
    for p in paths:
        r = fetch(urljoin(base, p))
        results[p] = r.get("status")
    return results

def run_nmap(host):
    if shutil.which("nmap") is None:
        return {"error": "nmap not installed"}
    try:
        out = subprocess.check_output(
            ["nmap","-Pn","-p","80,443",host],
            timeout=120, universal_newlines=True
        )
        return {"output": out[:2000]}
    except Exception as e:
        return {"error": str(e)}

# ================= REPORT =================

def save_report(target, data):
    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename,"w",encoding="utf-8") as f:
        f.write("SAFE RECON REPORT\n")
        f.write("="*60 + "\n\n")
        for k,v in data.items():
            f.write(f"{k}:\n")
            f.write(json.dumps(v, indent=2))
            f.write("\n\n")

    return filename

# ================= MAIN FLOW =================

def run_scan(level, target):
    data = {}
    norm = normalize(target)
    parsed = urlparse(norm)
    host = parsed.netloc.split(":")[0]

    console.print("\n[bold green][*][/bold green] Resolving DNS...")
    data["DNS"] = resolve_dns(host)

    console.print("[bold green][*][/bold green] Fetching HTTP info...")
    data["HTTP"] = fetch(norm)

    console.print("[bold green][*][/bold green] Checking TLS...")
    data["TLS"] = tls_info(host)

    console.print("[bold green][*][/bold green] Checking robots & security.txt...")
    data["robots"] = check_path(norm,"/robots.txt")
    data["securitytxt"] = check_path(norm,"/.well-known/security.txt")

    if level in ["2","3"]:
        console.print("[bold green][*][/bold green] Running extended directory scan...")
        data["Directories"] = simple_dirs(norm)

    if level == "3":
        console.print("[bold red][*][/bold red] Running active nmap scan...")
        data["Nmap"] = run_nmap(host)

    return data

# ================= ENTRY =================

def main():
    banner()

    while True:
        menu()
        choice = console.input("\nSelect option > ")

        if choice == "4":
            console.print("[red]Exiting...[/red]")
            break

        if choice not in ["1","2","3"]:
            console.print("[red]Invalid option[/red]")
            continue

        target = console.input("\nEnter target domain (example.com) > ")

        console.print("\n[cyan]Starting scan...[/cyan]\n")

        data = run_scan(choice, target)
        report_file = save_report(target.replace(".","_"), data)

        console.print(Panel(
            f"[bold green]Report saved:[/bold green]\n{report_file}",
            style="green"
        ))

if __name__ == "__main__":
    main()