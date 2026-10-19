# Contributing to Web Vulnerability Scanner

Thanks for your interest in improving the project! This guide covers how to set up,
test, and add new checks.

## Development setup

```bash
git clone https://github.com/Tawfiqimam0/webscan.git
cd webscan
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests and linters

```bash
pytest              # run the test suite
flake8 webscan      # lint
black webscan tests # format
```

## Adding a new scan module

Every check is a subclass of `ScanModule` (see `webscan/core/module.py`).

1. Create `webscan/modules/yourcheck.py`:

   ```python
   from typing import List
   from webscan.core.context import ScanContext
   from webscan.core.finding import Finding, Severity
   from webscan.core.module import ScanModule

   class YourCheckModule(ScanModule):
       name = "yourcheck"          # unique short name
       category = "web"            # recon | web | tls
       description = "What it does, one line."

       def run(self, ctx: ScanContext) -> List[Finding]:
           resp = ctx.http.get(ctx.target)
           if resp is None:
               return []
           # ... analyse resp, build findings ...
           return []
   ```

2. Register it in `webscan/modules/__init__.py` (import it and add to `ALL_MODULES`).

3. Add tests in `tests/` using the `make_ctx` fixture with a mocked handler.

### Module guidelines

- **Never raise** out of `run()` — the engine catches errors, but return cleanly where you can.
- **Be non-destructive.** Use harmless probes; never attempt real exploitation or data extraction.
- Pick an honest **severity**. Reserve `CRITICAL`/`HIGH` for confirmed, high-impact issues.
- Always set `remediation` and relevant `references` (CWE/OWASP) where possible.
- Respect `ctx.timeout` and `ctx.threads`.

## Commit style

- Keep commits focused and descriptive.
- Run tests and linters before opening a PR.

## Responsible use

Only submit checks intended for **authorized** testing. Do not add payloads designed to
damage, deface, or exfiltrate data from target systems.
