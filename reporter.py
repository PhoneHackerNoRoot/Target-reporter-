#!/usr/bin/env python3

import os
import subprocess
import datetime
import xml.etree.ElementTree as ET
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import pagesizes

# ==============================
# Banner
# ==============================

def banner():
    os.system("clear")
    print("\033[91m")
    print("██████╗ ██╗      █████╗  ██████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗")
    print("██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝")
    print("██████╔╝██║     ███████║██║     █████╔╝    ██║   ██████╔╝███████║██║     █████╗  ")
    print("██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ")
    print("██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗")
    print("╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝")
    print("\033[0m")
    print("        Passive & Active Recon V 1.0 ")
  
 """, style="bold red", box=box.DOUBLE))

# ==============================
# Risk Classification
# ==============================

def classify_risk(port, service):
    if port in [21, 23, 445, 3389]:
        return "HIGH"
    if "telnet" in service:
        return "CRITICAL"
    if "http" in service:
        return "MEDIUM"
    return "LOW"

# ==============================
# Nmap Scan
# ==============================

def run_scan(target):
    print("\n[*] Running scan...\n")
    xml_file = f"{target}_scan.xml"

    subprocess.run([
        "nmap", "-sV", "-sC", "-Pn",
        "-oX", xml_file,
        target
    ])

    return xml_file

# ==============================
# Parse XML
# ==============================

def parse_scan(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        for port in host.findall(".//port"):
            state = port.find("state").attrib["state"]
            if state != "open":
                continue

            port_id = int(port.attrib["portid"])
            service = port.find("service").attrib.get("name", "unknown")

            risk = classify_risk(port_id, service)

            findings.append((port_id, service, risk))

    return findings

# ==============================
# Generate PDF
# ==============================

def generate_pdf(target, findings):
    os.makedirs("reports", exist_ok=True)
    date = datetime.datetime.now().strftime("%Y-%m-%d")

    filename = f"reports/BLACKTRACE_{target}_{date}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=pagesizes.A4)

    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("BLACKTRACE Security Report", styles["Heading1"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {target}", styles["Normal"]))
    elements.append(Paragraph(f"Date: {date}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    data = [["Port", "Service", "Risk"]]

    for f in findings:
        data.append([str(f[0]), f[1], f[2]])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
    ]))

    elements.append(table)
    doc.build(elements)

    return filename

# ==============================
# Main Menu
# ==============================

def main_menu():
    while True:
        banner()
        print("1) Start Scan")
        print("2) Exit\n")

        choice = input("Select option > ")

        if choice == "1":
            target = input("\nEnter target (IP or domain): ")
            xml = run_scan(target)
            findings = parse_scan(xml)
            pdf = generate_pdf(target, findings)

            print(f"\n[+] Report generated: {pdf}")
            input("\nPress Enter to continue...")

        elif choice == "2":
            print("\nExiting BLACKTRACE...\n")
            break

        else:
            print("\nInvalid option.")
            input("Press Enter...")

# ==============================

if __name__ == "__main__":
    main_menu()