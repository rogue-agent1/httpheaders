#!/usr/bin/env python3
"""httpheaders - Inspect HTTP response headers with security analysis.

One file. Zero deps. Reads headers.

Usage:
  httpheaders.py https://example.com
  httpheaders.py https://example.com --security
  httpheaders.py https://example.com --filter content-type,server
  httpheaders.py https://example.com --json
"""

import argparse
import json
import ssl
import sys
import urllib.request
import urllib.error


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "Forces HTTPS connections"),
    "content-security-policy": ("CSP", "Controls resource loading"),
    "x-content-type-options": ("X-CTO", "Prevents MIME sniffing"),
    "x-frame-options": ("XFO", "Prevents clickjacking"),
    "x-xss-protection": ("X-XSS", "XSS filter (legacy)"),
    "referrer-policy": ("Referrer", "Controls referrer information"),
    "permissions-policy": ("Permissions", "Controls browser features"),
    "cross-origin-opener-policy": ("COOP", "Cross-origin isolation"),
    "cross-origin-resource-policy": ("CORP", "Cross-origin resource access"),
    "cross-origin-embedder-policy": ("COEP", "Cross-origin embedding"),
}


def fetch_headers(url: str, method: str = "HEAD", follow: bool = True, timeout: int = 10) -> dict:
    """Fetch HTTP headers from a URL."""
    ctx = ssl.create_default_context()
    
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "httpheaders/1.0",
        "Accept": "*/*",
    })

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {
                "url": resp.url,
                "status": resp.status,
                "headers": dict(resp.headers),
            }
    except urllib.error.HTTPError as e:
        return {
            "url": url,
            "status": e.code,
            "headers": dict(e.headers),
        }
    except Exception as e:
        return {"error": str(e)}


def security_check(headers: dict) -> list[dict]:
    """Check for security headers."""
    results = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, (short, desc) in SECURITY_HEADERS.items():
        present = header in lower_headers
        value = lower_headers.get(header, "")
        results.append({
            "header": header,
            "short": short,
            "description": desc,
            "present": present,
            "value": value[:80] if value else "",
        })

    return results


def main():
    parser = argparse.ArgumentParser(description="Inspect HTTP response headers")
    parser.add_argument("url", help="URL to inspect")
    parser.add_argument("--method", "-m", default="HEAD", choices=["HEAD", "GET"],
                        help="HTTP method (default: HEAD)")
    parser.add_argument("--security", "-s", action="store_true", help="Security header analysis")
    parser.add_argument("--filter", "-f", help="Comma-separated header names to show")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--timeout", "-t", type=int, default=10)

    args = parser.parse_args()

    result = fetch_headers(args.url, args.method, timeout=args.timeout)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        return 1

    headers = result["headers"]

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"  URL:    {result['url']}")
    print(f"  Status: {result['status']}")
    print()

    if args.security:
        checks = security_check(headers)
        present = sum(1 for c in checks if c["present"])
        total = len(checks)
        print(f"  Security Headers ({present}/{total}):")
        for c in checks:
            icon = "✓" if c["present"] else "✗"
            line = f"    {icon} {c['short']:<12} ({c['header']})"
            if c["value"]:
                line += f"\n      → {c['value']}"
            print(line)

        score = int(present / total * 100)
        grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F"
        print(f"\n  Score: {score}% (Grade: {grade})")
        return 0

    # Filter
    if args.filter:
        wanted = {h.strip().lower() for h in args.filter.split(',')}
        headers = {k: v for k, v in headers.items() if k.lower() in wanted}

    for k, v in sorted(headers.items()):
        print(f"  {k}: {v}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
