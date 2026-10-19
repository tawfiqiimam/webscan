# Usage Guide

A deeper walkthrough than the README quick-start.

## 1. Choosing a target

`webscan` accepts a full URL. If you omit the scheme, `https://` is assumed.

```bash
webscan example.com                       # becomes https://example.com
webscan https://example.com/app?id=1      # tests the id parameter too
```

The **injection checks (`sqli`, `xss`, `redirect`) only test query parameters.**
To test them, give a URL that has parameters, e.g. `?id=1` or `?q=test&next=/home`.
Without parameters those modules report an informational "skipped" result.

## 2. Selecting what runs

```bash
webscan URL --only headers,tls        # just these two
webscan URL --skip ports,dirs         # everything except these
webscan URL --category web            # only web-category modules
webscan --list-modules                # see all modules and categories
```

Selection precedence: `--only` wins outright; otherwise start from all modules,
narrow by `--category`, then remove anything in `--skip`.

## 3. Network behaviour

| Flag | Effect |
|---|---|
| `--timeout 15` | Wait up to 15s per request |
| `--threads 20` | Use 20 workers for the port & directory scans |
| `--insecure` | Skip TLS certificate verification (use with care) |
| `--header "Cookie: session=abc"` | Send extra headers; repeat the flag for more |

## 4. Reports

```bash
webscan URL --json out.json --html out.html
```

- **Console**: colour-coded, grouped by severity (highest first).
- **JSON**: full structured data — ideal for piping into other tools.
- **HTML**: a styled, shareable page with a severity summary and remediation.

## 5. Exit codes (useful in CI)

| Code | Meaning |
|---|---|
| `0` | No findings at/above the `--fail-on` threshold |
| `1` | At least one finding at/above the threshold |
| `2` | Usage or runtime error |

```bash
# Fail a pipeline if anything medium or worse is found
webscan https://staging.internal --fail-on medium --quiet || exit 1
```

## 6. Interpreting severities

| Severity | Meaning |
|---|---|
| `critical` | Confirmed high-impact issue (e.g. error-based SQLi) |
| `high` | Likely exploitable (e.g. unencoded reflected input) |
| `medium` | Real weakness needing attention (e.g. open redirect, weak TLS) |
| `low` | Hardening gap (e.g. missing clickjacking protection) |
| `info` | Context, recon data, or "nothing found" notes |

Findings are **heuristic**. Always manually verify before reporting them as confirmed
vulnerabilities.
