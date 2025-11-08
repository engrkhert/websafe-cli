#!/usr/bin/env python3
"""
site_scanner.py
A CLI website safety scanner with Rich UI and heuristic checks.
Optional: provide VirusTotal API key or Google Safe Browsing API key to strengthen checks.
"""

import argparse
import json
import re
import socket
import ssl
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

console = Console()

# ----------------------
# Helper / analysis funcs
# ----------------------

def fetch_url(url, timeout=12):
    """Fetch URL with simple error handling and return response (or None)."""
    headers = {"User-Agent": "SiteScanner/1.0 (+https://example.com)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
        return r
    except Exception as e:
        return None

def get_cert_info(hostname, port=443, timeout=8):
    """Return certificate subject and expiration info or None on failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

def domain_age_days(domain):
    """Return approximate domain age in days, or None."""
    try:
        w = whois.whois(domain)
        # whois can provide creation_date as datetime or list
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, datetime):
            return (datetime.utcnow() - cd).days
    except Exception:
        return None

def analyze_html(content):
    """Analyze HTML content for suspicious patterns. Return dict of findings and score."""
    findings = []
    score = 0

    soup = BeautifulSoup(content, "html.parser")
    text_content = soup.get_text(separator=" ", strip=True)[:2000]

    # 1) Suspicious script patterns
    scripts = soup.find_all("script")
    inline_count = sum(1 for s in scripts if not s.get("src"))
    external_count = sum(1 for s in scripts if s.get("src"))
    if inline_count > 5:
        findings.append(("Many inline scripts", "suspicious", f"{inline_count} inline <script> tags"))
        score += 6
    if external_count > 20:
        findings.append(("Many external scripts", "suspicious", f"{external_count} external scripts"))
        score += 4

    # look for eval, unescape, document.write, atob, long base64 strings
    suspicious_js_patterns = [
        (r"\beval\(", 4, "use of eval()"),
        (r"\bunescape\(", 3, "unescape()"),
        (r"\bdocument\.write\(", 3, "document.write()"),
        (r"\batob\(", 3, "atob() usage (base64 decoding)"),
        (r"data:text/javascript;base64,", 5, "embedded base64 JS"),
    ]
    for pat, pts, label in suspicious_js_patterns:
        if re.search(pat, content, re.IGNORECASE):
            findings.append((label, "high", label))
            score += pts

    # very long base64 strings
    if re.search(r"[A-Za-z0-9+/]{200,}={0,2}", content):
        findings.append(("Very long base64-like string", "suspicious", "Possible obfuscated payload"))
        score += 5

    # iFrame pointing to external suspicious sources
    iframes = soup.find_all("iframe")
    for ifr in iframes:
        src = ifr.get("src") or ""
        if src and not src.startswith("data:") and "youtube" not in src.lower():
            findings.append(("External iframe", "suspicious", f"iframe to {src}"))
            score += 3

    # forms that POST to suspicious endpoints (mailto or IP addresses)
    forms = soup.find_all("form")
    for f in forms:
        action = (f.get("action") or "").strip()
        if action:
            if action.startswith("mailto:"):
                findings.append(("Form posts to mailto", "suspicious", action))
                score += 3
            if re.match(r"https?://\d+\.\d+\.\d+\.\d+", action):
                findings.append(("Form posts to raw IP", "suspicious", action))
                score += 3

    # phishing-like terms in title or big visible text
    title = (soup.title.string if soup.title and soup.title.string else "") or ""
    phishing_terms = ["bank", "signin", "verify", "account", "login", "secure"]
    title_lower = title.lower()
    if any(term in title_lower for term in phishing_terms):
        findings.append(("Suspicious title terms", "medium", title))
        score += 2

    # missing critical security headers check will be done separately on response headers

    return {"score": score, "findings": findings, "preview": text_content}

def analyze_headers(headers):
    """Check for common security headers presence/absence and return findings & score impact."""
    findings = []
    score = 0
    # Headers of interest
    must_have = {
        "Content-Security-Policy": 3,
        "X-Frame-Options": 2,
        "Referrer-Policy": 1,
        "Strict-Transport-Security": 3,
    }
    for h, pts in must_have.items():
        if h not in headers:
            findings.append((f"Missing {h}", "medium", f"{h} not present"))
            score += pts
    # server header leakage
    server = headers.get("Server", "")
    if server:
        findings.append(("Server header present", "info", f"Server: {server}"))
    return {"score": score, "findings": findings}

def analyze_cert(cert):
    findings = []
    score = 0
    if not cert:
        findings.append(("No TLS certificate", "high", "No certificate or TLS handshake failed"))
        score += 8
        return {"score": score, "findings": findings}
    # expiry check
    try:
        not_after = cert.get("notAfter")
        if not_after:
            # cert notAfter format like 'Nov 10 12:00:00 2025 GMT'
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            if days_left < 0:
                findings.append(("Certificate expired", "high", f"expired {abs(days_left)} days ago"))
                score += 8
            elif days_left < 14:
                findings.append(("Certificate near expiry", "medium", f"{days_left} days left"))
                score += 3
    except Exception:
        pass
    return {"score": score, "findings": findings}

# ----------------------
# Optional: external API checks (VirusTotal / Google Safe Browsing)
# ----------------------
# Implemented as optional stubs that run only if keys are provided. We keep them lightweight
# to avoid mandatory API installation. If you want full integration, uncomment and install the
# respective SDKs and adapt.

def virustotal_lookup(domain_or_url, api_key=None):
    """If api_key provided, query VirusTotal v3 for URL or domain. Returns dict or None."""
    if not api_key:
        return None
    try:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        # VirusTotal expects URL to be submitted then analyzed id returned. For brevity, do a search endpoint:
        headers = {"x-apikey": api_key}
        # Try domain endpoint:
        search_url = f"https://www.virustotal.com/api/v3/domains/{domain_or_url}"
        r = requests.get(search_url, headers=headers, timeout=12)
        if r.status_code == 200:
            return r.json()
        # fallback - try url lookup flow (not fully implemented here)
    except Exception:
        return None
    return None

def google_safe_browsing_lookup(url, api_key=None):
    """If api_key provided, query Google Safe Browsing Lookup (v4) - simple request format.
    NOTE: This function expects a proper API key and may require enabling the API in GCP."""
    if not api_key:
        return None
    try:
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "site-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=12)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None

# ----------------------
# Aggregator & CLI output
# ----------------------

def score_to_verdict(total_score, threshold=8):
    """Simple mapping: lower is safer. threshold adjustable."""
    if total_score >= threshold:
        return "UNSAFE"
    elif total_score >= threshold / 2:
        return "SUSPICIOUS"
    else:
        return "SAFE"

def pretty_display_report(url, resp, html_analysis, header_analysis, cert_analysis, domain_days, vt_report=None, gsb_report=None, json_out=None):
    console.rule(f"[bold]Site Scanner Report[/bold] — {url}")
    table = Table.grid(expand=True)
    table.add_column(justify="left")
    table.add_column(justify="left")

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    # Header summary
    total_score = html_analysis["score"] + header_analysis["score"] + cert_analysis["score"]
    reasons = html_analysis["findings"] + header_analysis["findings"] + cert_analysis["findings"]
    # include external reports influence
    ext_msgs = []
    if vt_report:
        # crude interpretation: presence of attributes
        vt_flags = vt_report.get("data") or vt_report.get("attributes") or vt_report
        ext_msgs.append(("VirusTotal", "FOUND data (see raw)"))
        # If vt_report suggests malicious, bump score
        total_score += 10
    if gsb_report:
        if gsb_report.get("matches"):
            ext_msgs.append(("Google Safe Browsing", "MATCH(es) found"))
            total_score += 10
        else:
            ext_msgs.append(("Google Safe Browsing", "No matches"))

    verdict = score_to_verdict(total_score)

    # Top panel with verdict
    verdict_text = Text(verdict)
    if verdict == "SAFE":
        verdict_text.stylize("bold green")
    elif verdict == "SUSPICIOUS":
        verdict_text.stylize("bold yellow")
    else:
        verdict_text.stylize("bold red")

    left = Table.grid()
    left.add_row("Domain", domain)
    left.add_row("Resolved IP", resp.raw._connection.sock.getpeername()[0] if resp and getattr(resp, "raw", None) and getattr(resp.raw, "_connection", None) else "N/A")
    left.add_row("HTTP Status", str(resp.status_code) if resp else "No response")
    left.add_row("Content-Type", resp.headers.get("Content-Type","N/A") if resp else "N/A")
    left.add_row("Domain age (days)", str(domain_days) if domain_days is not None else "Unknown")
    left.add_row("Verdict", verdict_text)

    right = Table.grid()
    right.add_row("Total risk score", str(total_score))
    right.add_row("Security headers missing", str(len([f for f in header_analysis["findings"] if f[0].startswith("Missing")])))
    if ext_msgs:
        for tag, msg in ext_msgs:
            right.add_row(f"[bold]{tag}[/bold]: {msg}")

    table.add_row(Panel(left, title="Summary", box=box.ROUNDED), Panel(right, title="Score", box=box.ROUNDED))
    console.print(table)

    # Show preview
    preview = html_analysis.get("preview", "")[:2000]
    console.print(Panel(preview or "[no text preview]", title="Page preview (first 2k chars)", subtitle="text extracted from HTML", box=box.ROUNDED))

    # Findings list
    findings_table = Table(title="Findings (issues flagged)", box=box.SIMPLE_HEAVY)
    findings_table.add_column("Issue", no_wrap=True)
    findings_table.add_column("Severity", no_wrap=True)
    findings_table.add_column("Detail")
    if not reasons:
        findings_table.add_row("No obvious issues found by heuristics", "info", "")
    else:
        for (issue, sev, detail) in reasons:
            sev_txt = Text(sev.upper())
            if sev in ("high", "suspicious"):
                sev_txt.stylize("bold red")
            elif sev == "medium":
                sev_txt.stylize("yellow")
            else:
                sev_txt.stylize("green")
            findings_table.add_row(issue, sev_txt, detail)
    console.print(findings_table)

    # Certificates
    if cert_analysis["findings"]:
        cert_panel = Panel("\n".join(f"{i[0]} — {i[2]}" for i in cert_analysis["findings"]), title="Certificate issues", box=box.ROUNDED)
        console.print(cert_panel)

    # External raw data (optional)
    if vt_report:
        console.print(Panel("[italic]VirusTotal: raw JSON returned (truncated)[/italic]\n" + json.dumps(vt_report)[:2000], title="VirusTotal (truncated)", box=box.ROUNDED))
    if gsb_report:
        console.print(Panel("[italic]Google Safe Browsing report[/italic]\n" + json.dumps(gsb_report)[:2000], title="Google Safe Browsing (truncated)", box=box.ROUNDED))

    # JSON export
    if json_out:
        out = {
            "url": url,
            "total_score": total_score,
            "verdict": verdict,
            "html_analysis": html_analysis,
            "header_analysis": header_analysis,
            "cert_analysis": cert_analysis,
            "vt_report": vt_report,
            "gsb_report": gsb_report,
        }
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        console.print(f"[green]Wrote report JSON to {json_out}[/green]")

    # final color banner
    if verdict == "SAFE":
        console.rule("[bold green]SAFE ✅[/bold green]")
    elif verdict == "SUSPICIOUS":
        console.rule("[bold yellow]SUSPICIOUS ⚠️[/bold yellow]")
    else:
        console.rule("[bold red]UNSAFE ❌[/bold red]")

# ----------------------
# Main CLI
# ----------------------

def main():
    parser = argparse.ArgumentParser(description="SiteScanner — heuristic website safety scanner (CLI).")
    parser.add_argument("url", help="Target URL (include http/https)")
    parser.add_argument("--vt-key", help="VirusTotal API key (optional)", default=None)
    parser.add_argument("--gsb-key", help="Google Safe Browsing API key (optional)", default=None)
    parser.add_argument("--export-json", help="Write full report JSON to file", default=None)
    args = parser.parse_args()

    url = args.url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)

    # start progress UI
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeElapsedColumn(), transient=True) as prog:
        t = prog.add_task("Fetching site", total=None)
        resp = None
        try:
            resp = fetch_url(url)
            time.sleep(0.2)
        finally:
            prog.update(t, description="Analyzing content")
            prog.stop_task(t)

    if not resp:
        console.print(Panel(f"Failed to fetch {url}. The site may be down or blocked.", style="red"))
        return

    # analyze
    html_analysis = analyze_html(resp.text or "")
    header_analysis = analyze_headers({k: v for k, v in resp.headers.items()})
    hostname = parsed.hostname or parsed.path
    cert = get_cert_info(hostname)
    cert_analysis = analyze_cert(cert)
    domain_info_days = domain_age_days(hostname)

    # optional external checks
    vt_report = virustotal_lookup(hostname, api_key=args.vt_key) if args.vt_key else None
    gsb_report = google_safe_browsing_lookup(url, api_key=args.gsb_key) if args.gsb_key else None

    pretty_display_report(url, resp, html_analysis, header_analysis, cert_analysis, domain_info_days, vt_report=vt_report, gsb_report=gsb_report, json_out=args.export_json)

if __name__ == "__main__":
    main()