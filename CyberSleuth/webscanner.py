#!/usr/bin/env python3
import socket
import ssl
import json
import time
from typing import Dict, Any, List
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

USER_AGENT = "Defensive-Web-Scanner/1.0 (+https://example.local/)"
DEFAULT_TIMEOUT = 10
COMMON_ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/login", "/user", "/cpanel",
    "/phpmyadmin", "/manager/html", "/admin.php", "/admin/login.php"
]
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "expect-ct"
]


def canonicalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def fetch_http(url: str, method: str = "GET", allow_redirects: bool = True, timeout: int = DEFAULT_TIMEOUT):
    headers = {"User-Agent": USER_AGENT}
    try:
        if method.upper() == "HEAD":
            r = requests.head(url, headers=headers, allow_redirects=allow_redirects, timeout=timeout, verify=True)
        else:
            r = requests.get(url, headers=headers, allow_redirects=allow_redirects, timeout=timeout, verify=True)
        return {"ok": True, "status_code": r.status_code, "headers": dict(r.headers), "text": r.text, "url": r.url}
    except requests.exceptions.SSLError as e:
        return {"ok": False, "error": f"SSL error: {e}"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}


def get_tls_info(hostname: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                subject = cert.get("subject", ())
                issuer = cert.get("issuer", ())
                return {"ok": True, "notAfter": not_after, "subject": subject, "issuer": issuer}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    lower = {k.lower(): v for k, v in headers.items()}
    findings = {}
    for h in SECURITY_HEADERS:
        findings[h] = {"present": h in lower, "value": lower.get(h)}
    server = lower.get("server")
    findings["server_exposes_version"] = False
    findings["server_header"] = server
    if server and ("/" in server or any(ch.isdigit() for ch in server)):
        findings["server_exposes_version"] = True
    set_cookies = []
    raw_set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
    if raw_set_cookie:
        # best-effort split; may not catch all cookies perfectly
        parts = [p.strip() for p in raw_set_cookie.split(",")]
        for p in parts:
            set_cookies.append(p)
    findings["set_cookies"] = set_cookies
    cookie_issues = []
    for c in set_cookies:
        if "httponly" not in c.lower():
            cookie_issues.append({"cookie": c, "issue": "Missing HttpOnly"})
        if "secure" not in c.lower():
            cookie_issues.append({"cookie": c, "issue": "Missing Secure flag"})
    findings["cookie_issues"] = cookie_issues
    return findings


def check_robots_and_sitemap(base_url: str):
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots = fetch_http(urljoin(base, "/robots.txt"), method="GET")
    sitemap = fetch_http(urljoin(base, "/sitemap.xml"), method="GET")
    return {"robots_exists": robots.get("ok") and robots.get("status_code", 0) == 200,
            "sitemap_exists": sitemap.get("ok") and sitemap.get("status_code", 0) == 200,
            "robots_status": robots, "sitemap_status": sitemap}


def find_insecure_forms(html_text: str, page_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html_text or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        absolute_action = urljoin(page_url, action)
        insecure = False
        if absolute_action.startswith("http://"):
            insecure = True
        forms.append({"action": absolute_action, "method": method, "insecure_action": insecure})
    return forms


def quick_admin_path_checks(base_url: str, timeout: int = 6) -> List[Dict[str, Any]]:
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    headers = {"User-Agent": USER_AGENT}
    for path in COMMON_ADMIN_PATHS:
        url = urljoin(base, path)
        try:
            r = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
            results.append({"path": path, "url": url, "status_code": r.status_code})
            time.sleep(0.2)
        except Exception as e:
            results.append({"path": path, "url": url, "error": str(e)})
    return results


def scan_target(target: str, aggressive: bool = False) -> Dict[str, Any]:
    target = canonicalize_url(target)
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    report: Dict[str, Any] = {"target": target, "timestamp": int(time.time()), "errors": []}
    http = fetch_http(target, method="GET")
    report["http_fetch"] = http
    if not http.get("ok"):
        report["errors"].append({"stage": "http_fetch", "error": http.get("error")})
    else:
        report["security_headers"] = analyze_security_headers(http.get("headers", {}))
        report["insecure_forms"] = find_insecure_forms(http.get("text", ""), http.get("url"))

    if parsed.scheme == "https" or port == 443:
        tls = get_tls_info(host, port=port)
        report["tls"] = tls
        if not tls.get("ok"):
            report["errors"].append({"stage": "tls", "error": tls.get("error")})

    robots_sitemap = check_robots_and_sitemap(target)
    report["robots_sitemap"] = robots_sitemap

    if aggressive:
        admin_checks = quick_admin_path_checks(target)
        report["admin_path_checks"] = admin_checks

    return report


def pretty_print_report(rep: Dict[str, Any]):
    print(json.dumps(rep, indent=2, sort_keys=False))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Defensive web scanner (passive checks). Use only on authorized targets.")
    parser.add_argument("target", help="Target URL or domain (e.g. example.com or https://example.com)")
    parser.add_argument("--aggressive", action="store_true", help="Enable minimal active checks for common admin paths (use only with permission).")
    parser.add_argument("--output", "-o", help="Save JSON report to file")
    args = parser.parse_args()

    print("WARNING: Only scan systems you own or have explicit authorization to test.")
    report = scan_target(args.target, aggressive=args.aggressive)
    pretty_print_report(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
