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
            Created by khamidjanow
            Instagram @kham1djanow
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

from reportlab.platypus import Preformatted
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf(target, data):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/BLACKTRACE_{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    normal = styles["Normal"]
    wrap_style = ParagraphStyle('wrap', parent=styles['Normal'], fontSize=9, leading=12)
    mono_style = ParagraphStyle('mono', parent=styles['Normal'], fontName="Courier", fontSize=8, leading=10)
    risk_style = ParagraphStyle('risk', parent=styles['Normal'], fontSize=10, leading=12)

    # ---------- Executive Summary with Risk ----------
    high_risk = 0
    medium_risk = 0
    low_risk = 0

    # Count open ports in Nmap scan for risk scoring
    nmap_output = data.get("Nmap", {}).get("output", "")
    if nmap_output:
        for line in nmap_output.splitlines():
            if "open" in line.lower():
                port = int(line.split("/")[0])
                # example scoring: 80,443 high, 22,21 medium, others low
                if port in [80,443,3389,445]:
                    high_risk += 1
                elif port in [21,22,23]:
                    medium_risk += 1
                else:
                    low_risk += 1

    elements.append(Paragraph("BLACKTRACE Security Assessment Report", styles["Heading1"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {target}", normal))
    elements.append(Paragraph(f"Date: {datetime.datetime.now()}", normal))
    elements.append(Spacer(1, 20))

    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    elements.append(Spacer(1, 10))
    exec_summary = (
        "This report contains passive and active reconnaissance findings. "
        "Exposed services and configurations should be reviewed immediately."
    )
    elements.append(Paragraph(exec_summary, normal))
    elements.append(Spacer(1, 10))

    risk_summary = f"Risk Summary: [High: {high_risk}, Medium: {medium_risk}, Low: {low_risk}]"
    elements.append(Paragraph(risk_summary, risk_style))
    elements.append(Spacer(1, 20))

    # ---------- Detailed Sections ----------
    for section, content in data.items():
        elements.append(Paragraph(section, styles["Heading3"]))
        elements.append(Spacer(1, 8))

        if isinstance(content, dict):

            # Special case: Nmap
            if section == "Nmap" and "output" in content:
                # color-coding open ports
                lines = []
                for line in content["output"].splitlines():
                    if "open" in line.lower():
                        port = int(line.split("/")[0])
                        if port in [80,443,3389,445]:
                            lines.append(f'<font color="red">{line}</font>')
                        elif port in [21,22,23]:
                            lines.append(f'<font color="orange">{line}</font>')
                        else:
                            lines.append(f'<font color="green">{line}</font>')
                    else:
                        lines.append(line)
                elements.append(Preformatted("\n".join(lines), mono_style))
                elements.append(Spacer(1, 15))
                continue

            table_data = [
                [Paragraph("<b>Key</b>", normal), Paragraph("<b>Value</b>", normal)]
            ]

            for k, v in content.items():
                table_data.append([
                    Paragraph(str(k), wrap_style),
                    Paragraph(str(v), wrap_style)
                ])

            table = PDFTable(table_data, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.black),
                ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('GRID',(0,0),(-1,-1),0.5,colors.grey),
                ('VALIGN',(0,0),(-1,-1),'TOP')
            ]))

            elements.append(table)
            elements.append(Spacer(1, 15))
        else:
            elements.append(Paragraph(str(content), wrap_style))
            elements.append(Spacer(1, 15))

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
