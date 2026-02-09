#!/usr/bin/env python3

import os
import socket
import ssl
import shutil
import datetime
import subprocess
from urllib.parse import urlparse, urljoin
import requests

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as PDFTable, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

console = Console()
TIMEOUT = 10
USER_AGENT = "BLACKTRACE/2.0"

# ================= BANNER =================

def banner():
    os.system("clear")
    console.print(Panel("""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██████╔╝██║     ███████║██║     █████╔╝    ██║   ██████╔╝███████║██║     █████╗
██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██╔══██╗██╔══██║██║     ██╔══╝
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
        Passive & Active Recon Engine V 1.0
""", style="bold red", box=box.DOUBLE))

# ================= MENU =================

def menu():
    table = Table(title="SCAN LEVEL", box=box.ROUNDED)
    table.add_column("Option", justify="center", style="cyan")
    table.add_column("Mode", style="green")

    table.add_row("1", "Passive Scan")
    table.add_row("2", "Extended Scan")
    table.add_row("3", "Full Active Scan (nmap)")
    table.add_row("4", "Exit")

    console.print(table)

# ================= CORE FUNCTIONS =================

def normalize(target):
    return "https://" + target if not target.startswith("http") else target

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

def simple_dirs(base):
    paths = ["/admin","/login","/.git","/.env","/backup","/api"]
    results = {}
    for p in paths:
        try:
            r = requests.get(urljoin(base,p), timeout=TIMEOUT)
            results[p] = r.status_code
        except:
            results[p] = "error"
    return results

def run_nmap(host):
    if shutil.which("nmap") is None:
        return {"error": "nmap not installed"}

    try:
        out = subprocess.check_output(
            ["nmap","-sV","-Pn","-p","21,22,23,80,443,445,3389",host],
            timeout=180, universal_newlines=True
        )
        return {"output": out[:3000]}
    except Exception as e:
        return {"error": str(e)}

# ================= PDF REPORT =================

def generate_pdf(target, data):
    os.makedirs("reports", exist_ok=True)
    target_clean = target.replace("_", ".")
    filename = f"reports/BLACKTRACE_{target_clean}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("BLACKTRACE Security Assessment Report", styles["Heading1"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {target_clean}", styles["Normal"]))
    elements.append(Paragraph(f"Date: {datetime.datetime.now()}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        "This report contains passive and active reconnaissance findings. "
        "Exposed services and configurations should be reviewed immediately.",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    # --- Create PDF table for each section ---
    for section, content in data.items():
        elements.append(Paragraph(section, styles["Heading3"]))
        elements.append(Spacer(1, 6))

        if isinstance(content, dict):
            # If headers or dict, show as table
            table_data = [["Key", "Value"]]
            for k,v in content.items():
                table_data.append([str(k), str(v)[:500]])
            table = PDFTable(table_data, colWidths=[150, 350])
            table.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.grey),
                ('GRID',(0,0),(-1,-1),1,colors.black),
                ('TEXTCOLOR',(0,0),(-1,0),colors.white)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph(str(content), styles["Normal"]))
            elements.append(Spacer(1, 12))

    doc.build(elements)
    return filename

# ================= MAIN FLOW =================

def run_scan(level, target):
    data = {}
    norm = normalize(target)
    host = urlparse(norm).netloc.split(":")[0]

    console.print("\n[green][*] Resolving DNS...[/green]")
    data["DNS"] = resolve_dns(host)

    console.print("[green][*] Fetching HTTP...[/green]")
    data["HTTP"] = fetch(norm)

    console.print("[green][*] Checking TLS...[/green]")
    data["TLS"] = tls_info(host)

    if level in ["2","3"]:
        console.print("[green][*] Extended directory scan...[/green]")
        data["Directories"] = simple_dirs(norm)

    if level == "3":
        console.print("[red][*] Running full nmap scan...[/red]")
        data["Nmap"] = run_nmap(host)

    return data

# ================= ENTRY =================

def main():
    while True:
        banner()
        menu()
        choice = console.input("\nSelect option > ")

        if choice == "4":
            console.print("[red]Exiting BLACKTRACE...[/red]")
            break

        if choice not in ["1","2","3"]:
            console.print("[red]Invalid option[/red]")
            continue

        target = console.input("\nEnter target domain (example.com) > ")

        console.print("\n[cyan]Starting scan...[/cyan]")

        data = run_scan(choice, target)
        pdf = generate_pdf(target, data)

        console.print(Panel(
            f"[bold green]Report generated successfully[/bold green]\n{pdf}",
            style="green"
        ))

        console.input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
