<div align="center">

# 🛡️ Web Vulnerability Scanner

### `T4WF1Q`

**A professional, modular web application vulnerability scanner built in Python.**
Detect SQL Injection, XSS, CSRF, and other common web vulnerabilities — oriented around the OWASP Top 10.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Tawfiqimam0/webscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Tawfiqimam0/webscan/actions)
[![OWASP](https://img.shields.io/badge/focus-OWASP%20Top%2010-orange.svg)](https://owasp.org/www-project-top-ten/)

</div>

---

## 📋 Description

Develop a tool to scan websites for **SQL Injection, XSS, CSRF, and other vulnerabilities** using Python
and libraries like **BeautifulSoup** and **Requests**. The scanner automates the discovery of common web
application weaknesses and produces clear, actionable reports.

## 🎯 Skills Demonstrated

- **OWASP Top 10 vulnerabilities** — checks mapped to well-known web risk categories
- **Web security testing** — practical, non-destructive detection techniques
- **Automation & scripting** — a modular Python engine that runs many checks in one pass

## ✨ Key Features

- 🔍 **Detects common web app vulnerabilities** — SQLi, reflected XSS, CSRF, open redirects, missing security headers, TLS misconfiguration
- ⚙️ **Automated vulnerability scanning** — recon + web + TLS modules run with a single command
- 📊 **Reporting and alerting** — colour console output, machine-readable JSON, and a polished HTML report
- 🧩 **Modular architecture** — every check is a self-contained, pluggable module
- 🚦 **CI-friendly** — configurable `--fail-on` severity for use in pipelines

---

## 🧰 Modules

| Module | Category | What it does |
|---|---|---|
| `dns` | recon | Collects A/AAAA/MX/NS/TXT/CNAME records; flags missing SPF |
| `ports` | recon | Concurrent TCP connect scan of common service ports |
| `tech` | recon | Fingerprints servers, frameworks, and CMS platforms |
| `dirs` | recon | Probes for sensitive files and directories |
| `headers` | web | Flags missing security headers & information disclosure |
| `tls` | tls | Inspects certificate validity, expiry, and weak protocols |
| `xss` | web | Detects reflected XSS via unencoded marker reflection |
| `sqli` | web | Detects error-based SQL injection via DB error signatures |
| `redirect` | web | Detects open redirects in redirection-style parameters |
| `csrf` | web | Flags POST forms lacking an anti-CSRF token |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Tawfiqimam0/webscan.git
cd webscan

# (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install
pip install -e .
```

This installs a `webscan` command. You can also run it without installing:

```bash
pip install -r requirements.txt
python -m webscan.cli --help
```

---

## 💻 Usage

```bash
# Basic scan (runs all modules)
webscan https://example.com

# Test a URL with parameters for SQLi / XSS / open redirect
webscan "https://example.com/item?id=1&next=/home"

# Only run specific modules
webscan https://example.com --only headers,tls

# Run only web-category checks, skip DNS
webscan https://example.com --category web

# Save reports
webscan https://example.com --json report.json --html report.html

# Pass an auth header
webscan https://example.com --header "Authorization: Bearer <token>"

# CI mode: exit non-zero if anything medium or worse is found
webscan https://example.com --fail-on medium --quiet
```

### Common options

| Option | Description |
|---|---|
| `--only a,b` | Run only these modules |
| `--skip a,b` | Skip these modules |
| `--category recon,web,tls` | Run only these categories |
| `--timeout N` | Per-request timeout (seconds) |
| `--threads N` | Concurrency for port/dir scans |
| `--insecure` | Do not verify TLS certificates |
| `--header "K: V"` | Add a request header (repeatable) |
| `--json FILE` / `--html FILE` | Write reports |
| `--fail-on LEVEL` | Exit code 1 if a finding ≥ LEVEL exists |
| `--quiet` | Hide the banner and INFO findings |
| `--list-modules` | List available modules |

---

## 📄 Example Output

```
[INFO]     Technology detected: nginx
[CRITICAL] Possible SQL injection in parameter 'id'
[HIGH]     Possible reflected XSS in parameter 'q'
[MEDIUM]   Missing security header: content-security-policy
[LOW]      X-Frame-Options missing; the page may be vulnerable to clickjacking.

Summary: critical=1  high=1  medium=1  low=1  info=3
```

The HTML report renders the same findings as a styled, shareable page.

---

## ⚠️ Legal & Ethical Notice

This tool is for **authorized security testing and educational purposes only.**
Only scan systems that **you own** or have **explicit written permission** to test.
Unauthorized scanning may be illegal in your jurisdiction. The author assumes **no liability**
for misuse or damage caused by this program. See [LICENSE](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). A good first contribution is
a new module — implement `ScanModule`, drop it in `webscan/modules/`, and register it.

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">
Built with 🐍 and ☕ by <b>T4WF1Q</b>
</div>
