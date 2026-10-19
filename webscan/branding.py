"""Project branding shown in the CLI banner and reports."""

BRAND = "T4WF1Q"
TOOL_NAME = "Web Vulnerability Scanner"
TAGLINE = "Detect SQLi, XSS, CSRF and more — OWASP Top 10 oriented."

# ASCII banner printed at CLI start. Plain ASCII so it renders everywhere.
BANNER = r"""
 _____ _  _    _    _ _____ _  ___
|_   _| || |  | |  | |  ___/ |/ _ \
  | | | || |_ | |  | | |_  | | | | |
  | | |__   _|| |/\| |  _| | | |_| |
  |_|    |_|   \_/\_/|_|   |_|\__\_\

      Web Vulnerability Scanner  ::  by T4WF1Q
"""


def banner(version: str) -> str:
    return f"{BANNER}\n      v{version}  —  {TAGLINE}\n"
