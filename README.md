# Header Analyzer

HTTP response header analyzer with a dark GUI. Fetches headers from any URL via a local Python server, flags exposed fingerprints, checks for missing security headers, analyzes cookie flags and CORS policy, and computes a security score.

## Requirements

```
pip install flask flask-cors requests
```

## Setup

```bash
python header_server.py
```

Then open `header_analyzer.html` in your browser.

## Usage

Enter a URL in the search bar and click Analyze. The server fetches the headers and returns a full analysis.

## Pages

| Page | Description |
|---|---|
| Header Analyzer | Main view — URL input, header list, score, missing headers |
| History | All analyses from the current session, reloadable on click |
| Security Audit | Checklist of best practices, auto-checked if an analysis was run |
| Settings | Server port, timeout, User-Agent |
| About | Risk legend, version info, setup instructions |

## Output

| Column | Description |
|---|---|
| 🔴 Red | Critical issue — missing security header or exposed fingerprint |
| 🟡 Yellow | Warning — misconfigured header, weak cookie flags, CORS issue |
| 🟢 Green | Normal — standard header, no concern |

Security score is 0–100 based on present security headers minus penalties for exposed fingerprints.

## What it detects

- **Exposed fingerprints** — `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, etc.
- **Missing security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Cookie issues** — missing HttpOnly, Secure, SameSite flags
- **CORS** — wildcard `Access-Control-Allow-Origin`
- **CDN info** — Cloudflare, Fastly, AWS CloudFront via CF-Ray and IP ranges
