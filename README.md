![BLACKTRACE Logo](BLACKTRACE.png)
# BLACKTRACE - Passive & Active Recon Engine
Security assessment tool for authorized targets.  
**Eslatma:** Faqat ruxsatli domenda ishlating.
---

# ⚠️ IMPORTANT SYSTEM NOTICE

## ❌ TERMUX IS NOT SUPPORTED

### This tool does **NOT** work in Termux.

---

# ✅ SUPPORTED OPERATING SYSTEMS

- **Linux**
- **Windows**
- **macOS**
- **Kali NetHunter**

---

## Quick Start

```bash
git clone https://github.com/Cyber-Securyt-tools-builder/BLACKTRACE.git
```
Select folder
```bash
cd BLACKTRACE
```
Run the python virtual environment step-1
```bash
python3 -m venv venv
```
Run the python virtual environment step-2
```bash
source venv/bin/activate
```
Download modules
```bash
pip install -r requirements.txt
```
Run the tool
```bash
python3 reporter.py

```
📘 User Guide (Usage Guide)

🔹 What is BLACKTRACE?

BLACKTRACE is a Passive & Active Reconnaissance tool designed for authorized targets only.

The tool can check:

DNS information

HTTP headers

TLS/SSL certificate details

Important directory existence

Open ports (via nmap)

Risk scoring (High / Medium / Low)


It generates professional PDF reports for easy review.


---

🔹 Scan Levels

1.Passive Scan

DNS resolution

HTTP headers

TLS certificate

robots.txt / security.txt


Minimal impact on target.


---

2. Extended Scan

Passive + additional directory checks:

/admin

/login

/.git

/.env

/backup

/api



---

3. Full Active Scan

Extended + Nmap port scanning:

Scanned ports:

21 (FTP)

22 (SSH)

23 (Telnet)

80 (HTTP)

443 (HTTPS)

445 (SMB)

3389 (RDP)


Open ports are classified by risk levels.


---

📊 Risk Scoring

PDF report includes automatic risk scoring:

🔴 High Risk

80

443

3389

445


🟠 Medium Risk

21

22

23


🟢 Low Risk

Other open ports


The Risk Summary is calculated automatically.


---

📄 Report Structure

The PDF contains:

Executive Summary

Risk Summary

DNS Information

HTTP Headers

TLS Certificate Details

Directory Findings

Nmap Scan Output

Color-coded open ports for easy identification


Reports are ready for company submission.


---

⚠️ Important Notes

Only use on targets you own or are authorized to test.

Unauthorized scanning may be illegal.

BLACKTRACE does not exploit vulnerabilities, it only identifies them.

Active Scan sends real network requests.



---

🛠 Technical Requirements

Python 3.9+

requests

rich

reportlab

nmap (for Active Scan)



---

📁 Report Storage

Reports are automatically saved in:

reports/BLACKTRACE_target_YYYYMMDD_HHMMSS.pdf


---

🔐 Professional Recommendation

For company submission:

Include the Executive Summary in the email body

Attach the PDF report

Highlight the Risk Summary separately



---



