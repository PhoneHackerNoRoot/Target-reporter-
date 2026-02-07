#!/usr/bin/env python3
"""
safe_recon_reporter.py
Avtomatlashtirilgan, **passive-first** recon va hisobot yaratish tool'i.
FAOLIYATNI BOSHLAMASDAN OLDIN: faqat ruxsatli yoki o'z domenlaringizda ishlating.

Foydalanish:
    python3 safe_recon_reporter.py --target example.com --out report.txt

Options:
    --target    : domain yoki URL (majburiy)
    --out       : chiqish fayli (default: hisobot.txt)
    --enable-active : agar belgilansa, nmap/nikto/dirsearch kabi asboblarga chaqiriqlar qo'shiladi
    --email     : agar set qilinsa, yakuniy hisobotga e-mail shabloni qo'shiladi (masalan security@example.com)
"""

import sys
import argparse
import socket
import subprocess
import shutil
import datetime
import json
from urllib.parse import urlparse, urljoin
import requests

# --- Config ---
TIMEOUT = 10
USER_AGENT = "SafeReconReporter/1.0 (+https://example.invalid)"
# ----------------

def normalize_target(t):
    if not t.startswith("http://") and not t.startswith("https://"):
        return "https://" + t
    return t

def fetch_url(url):
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        return {
            "status_code": r.status_code,
            "final_url": r.url,
            "headers": dict(r.headers),
            "body_snippet": r.text[:4000]
        }
    except Exception as e:
        return {"error": str(e)}

def get_tls_info(hostname, port=443):
    try:
        import ssl, OpenSSL
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
        subj = x509.get_subject()
        issuer = x509.get_issuer()
        not_before = x509.get_notBefore().decode()
        not_after = x509.get_notAfter().decode()
        return {
            "subject": dict(x509.get_subject().get_components()),
            "issuer": dict(x509.get_issuer().get_components()),
            "valid_from": not_before,
            "valid_to": not_after
        }
    except Exception as e:
        return {"error": str(e)}

def resolve_a(hostname):
    try:
        return socket.gethostbyname_ex(hostname)
    except Exception as e:
        return {"error": str(e)}

def check_security_txt(base_url):
    try:
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        res = fetch_url(urljoin(root, "/.well-known/security.txt"))
        return res
    except Exception as e:
        return {"error": str(e)}

def check_robots_txt(base_url):
    try:
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        res = fetch_url(urljoin(root, "/robots.txt"))
        return res
    except Exception as e:
        return {"error": str(e)}

def simple_dirscan(base_url, wordlist=None, max_paths=50):
    # very simple: try common paths. NOT exhaustive. Passive/benign.
    common = [
        "/", "/admin", "/login", "/dashboard", "/api", "/.git", "/backup", "/config", "/server-status",
        "/robots.txt", "/.env", "/wp-admin", "/xmlrpc.php"
    ]
    if wordlist:
        common += wordlist[:max_paths]
    results = {}
    for p in common:
        u = urljoin(base_url, p)
        r = fetch_url(u)
        results[p] = {"status": r.get("status_code") if "status_code" in r else None}
    return results

def call_external_if_allowed(cmd, enabled):
    if not enabled:
        return {"skipped": True, "cmd": cmd}
    if shutil.which(cmd[0]) is None:
        return {"error": f"{cmd[0]} not found on PATH", "cmd": cmd}
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=300, universal_newlines=True)
        return {"output": out}
    except subprocess.CalledProcessError as e:
        return {"error": "non-zero exit", "output": e.output}
    except Exception as e:
        return {"error": str(e)}

def build_report(data, out_path, email_target=None):
    now = datetime.datetime.utcnow().isoformat() + "Z"
    lines = []
    lines.append(f"SafeReconReporter - Report")
    lines.append(f"Generated: {now}")
    lines.append("="*60)
    lines.append("")
    lines.append("TARGET SUMMARY")
    lines.append("-"*40)
    lines.append(f"Target: {data.get('target')}")
    lines.append(f"Normalized URL: {data.get('normalized')}")
    lines.append(f"Resolved: {json.dumps(data.get('dns',{}), indent=2)}")
    lines.append("")
    lines.append("HTTP(S) SUMMARY")
    lines.append("-"*40)
    http = data.get("http_summary",{})
    lines.append(f"Final URL: {http.get('final_url')}")
    lines.append(f"Status code: {http.get('status_code')}")
    lines.append("Headers:")
    for k,v in (http.get("headers") or {}).items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("TLS / Certificate Info")
    lines.append("-"*40)
    tls = data.get("tls", {})
    if tls and "error" not in tls:
        lines.append(f"Issuer: {tls.get('issuer')}")
        lines.append(f"Subject: {tls.get('subject')}")
        lines.append(f"Valid from/to: {tls.get('valid_from')} - {tls.get('valid_to')}")
    else:
        lines.append(f"TLS check error / skipped: {tls.get('error')}")
    lines.append("")
    lines.append("robots.txt")
    lines.append("-"*40)
    robots = data.get("robots",{})
    if robots and "error" not in robots:
        lines.append(f"Status: {robots.get('status_code')}")
        snippet = robots.get("body_snippet","")
        lines.append("Snippet:")
        lines.append(snippet[:1000])
    else:
        lines.append(f"robots.txt: {robots.get('error')}")
    lines.append("")
    lines.append("security.txt")
    lines.append("-"*40)
    sec = data.get("securitytxt",{})
    if sec and "error" not in sec:
        lines.append(f"Status: {sec.get('status_code')}")
        lines.append("Snippet:")
        lines.append(sec.get("body_snippet","")[:1000])
    else:
        lines.append(f"security.txt: {sec.get('error')}")
    lines.append("")
    lines.append("SIMPLE DIRECTORY CHECK (sample)")
    lines.append("-"*40)
    for p,info in (data.get("dirs") or {}).items():
        lines.append(f"{p} -> {info.get('status')}")
    lines.append("")
    lines.append("EXTERNAL TOOLS (if enabled)")
    lines.append("-"*40)
    for k,v in (data.get("external") or {}).items():
        lines.append(f"{k}: {json.dumps(v)[:200]}")
    lines.append("")
    lines.append("="*60)
    lines.append("RECOMMENDATIONS (general, non-exhaustive)")
    lines.append("- use HSTS, limit HTTP methods, sanitize inputs, keep software up-to-date, check exposed files like .env/.git, maintain security.txt with triage contacts.")
    lines.append("")
    lines.append("="*60)
    if email_target:
        lines.append("EMAIL TEMPLATE (ready to send)")
        lines.append("-"*40)
        lines.append(f"To: {email_target}")
        lines.append("Subject: Security finding - passive reconnaissance summary")
        lines.append("")
        lines.append("Hello,\n\nI performed a passive security reconnaissance of your domain (authorized). Attached is a short summary of findings and recommendations. Please let me know if you'd like a more detailed report or coordinated disclosure steps.\n\nBest regards,\n[Your name / handle]")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="domain or URL to scan (only if you have permission)")
    parser.add_argument("--out", default="hisobot.txt", help="output report filename")
    parser.add_argument("--enable-active", action="store_true", help="enable optional external tools (nmap/nikto) if installed")
    parser.add_argument("--email", default=None, help="optional email to include in template")
    args = parser.parse_args()

    norm = normalize_target(args.target)
    parsed = urlparse(norm)
    hostname = parsed.netloc.split(":")[0]

    print("[*] Starting passive reconnaissance (make sure you have permission to test this target).")

    data = {"target": args.target, "normalized": norm}

    print("[*] Resolving DNS...")
    data["dns"] = resolve_a(hostname)

    print("[*] Fetching main page headers...")
    data["http_summary"] = fetch_url(norm)

    print("[*] Checking TLS / certificate info...")
    data["tls"] = get_tls_info(hostname)

    print("[*] Fetching robots.txt and security.txt...")
    data["robots"] = check_robots_txt(norm)
    data["securitytxt"] = check_security_txt(norm)

    print("[*] Performing simple directory check (benign)...")
    data["dirs"] = simple_dirscan(norm)

    print("[*] Running optional external tools (if enabled)...")
    external = {}
    # note: these are optional and only run if --enable-active is set
    external["nmap"] = call_external_if_allowed(["nmap", "-Pn", "-sS", hostname, "-p", "80,443,8080"], args.enable_active)
    external["nikto"] = call_external_if_allowed(["nikto", "-h", norm], args.enable_active)
    data["external"] = external

    print("[*] Building report...")
    out = build_report(data, args.out, email_target=args.email)
    print(f"[+] Report written to: {out}")
    print("[*] Done. Remember: use this report only in a lawful, responsible way.")

if __name__ == "__main__":
    main()
