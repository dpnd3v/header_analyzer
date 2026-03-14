"""
Header Analyzer - OSINT Tool
Local proxy server for the GUI. Fetches HTTP headers and returns analysis as JSON.

Dependencies:
    pip install flask flask-cors requests

Python >= 3.11 recommended.
"""

import json
import socket
import ipaddress
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

HEADER_DB = {
    "strict-transport-security": {
        "category": "security",
        "risk": "red",
        "risk_label": "Critical",
        "description": "Forces HTTPS. Missing = downgrade attacks possible.",
        "good": True,
    },
    "content-security-policy": {
        "category": "security",
        "risk": "red",
        "risk_label": "Critical",
        "description": "Controls allowed content sources. Missing = XSS risk.",
        "good": True,
    },
    "x-frame-options": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Prevents clickjacking. Deprecated by CSP frame-ancestors.",
        "good": True,
    },
    "x-content-type-options": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Prevents MIME-type sniffing. Should be 'nosniff'.",
        "good": True,
    },
    "referrer-policy": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Controls referrer info sent with requests.",
        "good": True,
    },
    "permissions-policy": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Controls browser feature access (camera, mic, geolocation).",
        "good": True,
    },
    "cross-origin-opener-policy": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Isolates browsing context. Mitigates Spectre attacks.",
        "good": True,
    },
    "cross-origin-embedder-policy": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Controls cross-origin resource embedding.",
        "good": True,
    },
    "cross-origin-resource-policy": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Controls cross-origin resource loading.",
        "good": True,
    },
    "x-xss-protection": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Legacy XSS filter. Deprecated — use CSP instead.",
        "good": True,
    },
    "server": {
        "category": "fingerprint",
        "risk": "red",
        "risk_label": "Exposure",
        "description": "Reveals web server software and version.",
        "good": False,
    },
    "x-powered-by": {
        "category": "fingerprint",
        "risk": "red",
        "risk_label": "Exposure",
        "description": "Reveals backend language/framework (PHP, ASP.NET, etc.).",
        "good": False,
    },
    "x-aspnet-version": {
        "category": "fingerprint",
        "risk": "red",
        "risk_label": "Exposure",
        "description": "Reveals exact ASP.NET version. Remove immediately.",
        "good": False,
    },
    "x-aspnetmvc-version": {
        "category": "fingerprint",
        "risk": "red",
        "risk_label": "Exposure",
        "description": "Reveals ASP.NET MVC version.",
        "good": False,
    },
    "x-generator": {
        "category": "fingerprint",
        "risk": "red",
        "risk_label": "Exposure",
        "description": "Reveals CMS or generator (WordPress, Drupal, etc.).",
        "good": False,
    },
    "x-drupal-cache": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Exposure",
        "description": "Reveals Drupal CMS usage.",
        "good": False,
    },
    "x-wordpress-cache": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Exposure",
        "description": "Reveals WordPress CMS usage.",
        "good": False,
    },
    "via": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Info",
        "description": "Reveals proxy/CDN infrastructure path.",
        "good": False,
    },
    "x-varnish": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Info",
        "description": "Reveals Varnish cache usage and request IDs.",
        "good": False,
    },
    "x-cache": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Info",
        "description": "Cache status from CDN or proxy.",
        "good": False,
    },
    "x-cache-hits": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Info",
        "description": "Number of cache hits.",
        "good": False,
    },
    "cf-cache-status": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Info",
        "description": "Cloudflare cache status.",
        "good": False,
    },
    "cf-ray": {
        "category": "cdn",
        "risk": "green",
        "risk_label": "Info",
        "description": "Cloudflare request ID. Confirms Cloudflare CDN.",
        "good": False,
    },
    "cf-connecting-ip": {
        "category": "cdn",
        "risk": "green",
        "risk_label": "Info",
        "description": "Original client IP as seen by Cloudflare.",
        "good": False,
    },
    "content-type": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "MIME type of the response body.",
        "good": True,
    },
    "content-length": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Size of the response body in bytes.",
        "good": True,
    },
    "content-encoding": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Compression method used (gzip, br, etc.).",
        "good": True,
    },
    "transfer-encoding": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Transfer encoding (chunked, etc.).",
        "good": True,
    },
    "cache-control": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Caching directives for browsers and proxies.",
        "good": True,
    },
    "expires": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Legacy cache expiry date.",
        "good": True,
    },
    "etag": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Resource version identifier for conditional requests.",
        "good": True,
    },
    "last-modified": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Last modification timestamp of the resource.",
        "good": True,
    },
    "location": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Redirect target URL.",
        "good": True,
    },
    "access-control-allow-origin": {
        "category": "cors",
        "risk": "yellow",
        "risk_label": "CORS",
        "description": "CORS allowed origins. '*' = open to all domains.",
        "good": True,
    },
    "access-control-allow-methods": {
        "category": "cors",
        "risk": "green",
        "risk_label": "CORS",
        "description": "Allowed HTTP methods for CORS requests.",
        "good": True,
    },
    "access-control-allow-headers": {
        "category": "cors",
        "risk": "green",
        "risk_label": "CORS",
        "description": "Allowed headers in CORS requests.",
        "good": True,
    },
    "access-control-allow-credentials": {
        "category": "cors",
        "risk": "yellow",
        "risk_label": "CORS",
        "description": "Allows cookies in cross-origin requests.",
        "good": True,
    },
    "set-cookie": {
        "category": "cookies",
        "risk": "yellow",
        "risk_label": "Cookie",
        "description": "Sets a cookie. Check for HttpOnly, Secure, SameSite flags.",
        "good": True,
    },
    "www-authenticate": {
        "category": "auth",
        "risk": "yellow",
        "risk_label": "Auth",
        "description": "Authentication challenge. Reveals auth mechanism.",
        "good": True,
    },
    "authorization": {
        "category": "auth",
        "risk": "red",
        "risk_label": "Critical",
        "description": "Authorization token. Should never appear in responses.",
        "good": False,
    },
    "date": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Date and time the response was sent.",
        "good": True,
    },
    "age": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Seconds the response has been cached.",
        "good": True,
    },
    "vary": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Response varies based on these request headers.",
        "good": True,
    },
    "alt-svc": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Advertises alternative services (HTTP/3, QUIC).",
        "good": True,
    },
    "link": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Related resources (preload, canonical, etc.).",
        "good": True,
    },
    "x-request-id": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Info",
        "description": "Internal request identifier. May reveal infrastructure.",
        "good": False,
    },
    "x-runtime": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Exposure",
        "description": "Server-side processing time. Reveals performance characteristics.",
        "good": False,
    },
    "x-response-time": {
        "category": "fingerprint",
        "risk": "yellow",
        "risk_label": "Info",
        "description": "Response time in ms. Reveals backend performance.",
        "good": False,
    },
    "nel": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Network Error Logging configuration.",
        "good": True,
    },
    "report-to": {
        "category": "general",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Reporting endpoint for browser policy violations.",
        "good": True,
    },
    "expect-ct": {
        "category": "security",
        "risk": "yellow",
        "risk_label": "Medium",
        "description": "Certificate Transparency enforcement. Deprecated.",
        "good": True,
    },
    "pragma": {
        "category": "cache",
        "risk": "green",
        "risk_label": "Normal",
        "description": "Legacy HTTP/1.0 cache control directive.",
        "good": True,
    },
}

SECURITY_REQUIRED = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

FINGERPRINT_DANGEROUS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


def analyze_cookie(value: str) -> dict:
    flags = []
    issues = []
    v_lower = value.lower()
    if "httponly" in v_lower:
        flags.append("HttpOnly")
    else:
        issues.append("missing HttpOnly")
    if "secure" in v_lower:
        flags.append("Secure")
    else:
        issues.append("missing Secure")
    if "samesite" in v_lower:
        if "samesite=none" in v_lower:
            flags.append("SameSite=None")
            issues.append("SameSite=None is risky")
        elif "samesite=lax" in v_lower:
            flags.append("SameSite=Lax")
        elif "samesite=strict" in v_lower:
            flags.append("SameSite=Strict")
    else:
        issues.append("missing SameSite")
    return {"flags": flags, "issues": issues}


def analyze_cors(value: str) -> dict:
    issues = []
    if value.strip() == "*":
        issues.append("wildcard origin — any domain can make requests")
    return {"issues": issues}


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    if request.method == "POST":
        data = request.get_json()
        url = data.get("url", "").strip()
    else:
        url = request.args.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; HeaderAnalyzer-OSINT/1.0)"},
            verify=False,
        )
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; HeaderAnalyzer-OSINT/1.0)"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    headers_raw = dict(resp.headers)
    headers_lower = {k.lower(): v for k, v in headers_raw.items()}

    analyzed = []
    for name, value in headers_raw.items():
        name_lower = name.lower()
        info = HEADER_DB.get(name_lower, {
            "category": "other",
            "risk": "green",
            "risk_label": "Normal",
            "description": "Non-standard or custom header.",
            "good": True,
        })

        entry = {
            "name": name,
            "value": value,
            "risk": info["risk"],
            "risk_label": info["risk_label"],
            "category": info["category"],
            "description": info["description"],
            "notes": [],
        }

        if name_lower == "set-cookie":
            cookie_analysis = analyze_cookie(value)
            entry["notes"] = cookie_analysis["issues"]
            if cookie_analysis["issues"]:
                entry["risk"] = "yellow"

        if name_lower == "access-control-allow-origin":
            cors_analysis = analyze_cors(value)
            entry["notes"] = cors_analysis["issues"]
            if cors_analysis["issues"]:
                entry["risk"] = "red"
                entry["risk_label"] = "Critical"

        analyzed.append(entry)

    missing_security = []
    for h in SECURITY_REQUIRED:
        if h not in headers_lower:
            info = HEADER_DB.get(h, {})
            missing_security.append({
                "name": h,
                "risk": info.get("risk", "red"),
                "risk_label": info.get("risk_label", "Missing"),
                "description": info.get("description", ""),
            })

    exposed_fingerprint = []
    for h in FINGERPRINT_DANGEROUS:
        if h in headers_lower:
            exposed_fingerprint.append({
                "name": h,
                "value": headers_lower[h],
            })

    counts = {"red": 0, "yellow": 0, "green": 0}
    for h in analyzed:
        counts[h["risk"]] = counts.get(h["risk"], 0) + 1
    for h in missing_security:
        counts["red"] += 1

    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "-"

    result = {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "ip": ip,
        "headers": analyzed,
        "missing_security": missing_security,
        "exposed_fingerprint": exposed_fingerprint,
        "counts": counts,
        "total": len(analyzed),
    }

    return jsonify(result)


@app.route("/ping")
def ping():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    print("\n[*] Header Analyzer server running on http://localhost:5000")
    print("[*] Open header_analyzer.html in your browser\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
