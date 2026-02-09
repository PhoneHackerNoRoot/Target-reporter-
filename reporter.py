import os
import json
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import ListFlowable
from reportlab.lib.pagesizes import A4

# ==============================
# BLACKTRACE Banner
# ==============================

def banner():
    print("""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██████╔╝██║     ███████║██║     █████╔╝    ██║   ██████╔╝███████║██║     █████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗    ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝

        Passive & Active Recon Engine (Audit Edition)
    """)

# ==============================
# Load Scan Results
# ==============================

def load_results():
    if not os.path.exists("scan_results.json"):
        print("[!] scan_results.json topilmadi.")
        return None
    
    with open("scan_results.json", "r") as f:
        return json.load(f)

# ==============================
# PDF Generator
# ==============================

def generate_pdf(target, open_ports, vulnerable_services):
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"reports/BLACKTRACE_{target.replace('.', '_')}_{date_str}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = styles["Heading1"]
    normal_style = styles["Normal"]
    
    elements.append(Paragraph("BLACKTRACE Security Assessment Report", title_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    elements.append(Paragraph(f"Target: {target}", normal_style))
    elements.append(Paragraph(f"Assessment Date: {date_str}", normal_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    elements.append(Paragraph("Executive Summary:", styles["Heading2"]))
    elements.append(Paragraph(
        "This report outlines the security posture of the target system based on authorized reconnaissance activities. "
        "The assessment identifies exposed services and potential security risks.",
        normal_style
    ))
    elements.append(Spacer(1, 0.3 * inch))
    
    # Open Ports
    elements.append(Paragraph("Open Ports Detected:", styles["Heading2"]))
    
    if open_ports:
        port_list = [ListItem(Paragraph(f"Port {p['port']} - {p['service']}", normal_style)) for p in open_ports]
        elements.append(ListFlowable(port_list))
    else:
        elements.append(Paragraph("No open ports detected.", normal_style))
    
    elements.append(Spacer(1, 0.3 * inch))
    
    # Vulnerabilities
    elements.append(Paragraph("Potentially Vulnerable Services:", styles["Heading2"]))
    
    if vulnerable_services:
        vuln_list = [ListItem(Paragraph(
            f"{v['service']} (Port {v['port']}): {v['issue']}",
            normal_style)) for v in vulnerable_services]
        elements.append(ListFlowable(vuln_list))
    else:
        elements.append(Paragraph("No obvious vulnerable services identified.", normal_style))
    
    elements.append(Spacer(1, 0.5 * inch))
    
    elements.append(Paragraph(
        "Recommendation: It is advised to review exposed services, close unused ports, "
        "and ensure all software components are updated to their latest secure versions.",
        normal_style
    ))
    
    doc.build(elements)
    print(f"[+] Report generated: {filename}")

# ==============================
# Main
# ==============================

def main():
    banner()
    
    target = input("Enter target domain or IP: ").strip()
    
    print("\n[+] Loading scan results...")
    results = load_results()
    
    if results is None:
        return
    
    open_ports = results.get("open_ports", [])
    vulnerable_services = results.get("vulnerable_services", [])
    
    print("[+] Generating professional security report...")
    generate_pdf(target, open_ports, vulnerable_services)
    
    print("\n[✓] BLACKTRACE Audit Completed.")

if __name__ == "__main__":
    main()