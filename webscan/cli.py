"""Command-line interface for the T4WF1Q Web Vulnerability Scanner."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List

from webscan import __version__
from webscan.branding import banner
from webscan.core.engine import Engine
from webscan.core.finding import Severity
from webscan.modules import ALL_MODULES, build_modules
from webscan.reporters import ConsoleReporter, HTMLReporter, JSONReporter

LOG = logging.getLogger("webscan")

# Exit codes: 0 clean, 1 findings at/above threshold, 2 usage/runtime error.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webscan",
        description="T4WF1Q Web Vulnerability Scanner — SQLi, XSS, CSRF, headers, TLS, recon.",
        epilog="Only scan systems you own or are explicitly authorized to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Target URL, e.g. https://example.com/page?id=1")
    p.add_argument("--version", action="version", version=f"webscan {__version__}")
    p.add_argument("--list-modules", action="store_true", help="List available modules and exit.")

    sel = p.add_argument_group("module selection")
    sel.add_argument("--only", help="Comma-separated module names to run exclusively.")
    sel.add_argument("--skip", help="Comma-separated module names to skip.")
    sel.add_argument(
        "--category",
        help="Only run modules in these categories (comma-separated: recon,web,tls).",
    )

    net = p.add_argument_group("network")
    net.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s). Default 10.")
    net.add_argument("--threads", type=int, default=10, help="Concurrency for port/dir scans. Default 10.")
    net.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    net.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="K:V",
        help="Extra request header (repeatable), e.g. --header 'Authorization: Bearer x'.",
    )

    out = p.add_argument_group("output")
    out.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE.")
    out.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE.")
    out.add_argument("--quiet", action="store_true", help="Suppress the banner and INFO findings.")
    out.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default="high",
        help="Exit non-zero if a finding at/above this severity exists. Default: high.",
    )
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    return p


def _parse_headers(raw: List[str]) -> dict:
    headers = {}
    for item in raw:
        if ":" not in item:
            continue
        key, _, value = item.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def _normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def list_modules() -> None:
    print("Available modules:\n")
    for name, cls in ALL_MODULES.items():
        print(f"  {name:<10} [{cls.category:<5}] {cls.description}")
    print("\nCategories: recon, web, tls")


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.list_modules:
        list_modules()
        return EXIT_CLEAN

    if not args.target:
        parser.error("a target is required (or use --list-modules)")

    if not args.quiet:
        print(banner(__version__))

    target = _normalize_target(args.target)

    only = [s.strip() for s in args.only.split(",")] if args.only else None
    skip = [s.strip() for s in args.skip.split(",")] if args.skip else None
    cats = [s.strip() for s in args.category.split(",")] if args.category else None

    modules = build_modules(only=only, skip=skip, categories=cats)
    if not modules:
        LOG.error("No modules selected.")
        return EXIT_ERROR

    print(f"[*] Scanning {target} with {len(modules)} module(s)...\n")

    engine = Engine(
        target=target,
        modules=modules,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        threads=args.threads,
        extra_headers=_parse_headers(args.header),
    )
    result = engine.run()

    ConsoleReporter(show_info=not args.quiet).render(result)

    if args.json:
        JSONReporter().write(result, args.json)
        print(f"\n[+] JSON report written to {args.json}")
    if args.html:
        HTMLReporter().write(result, args.html)
        print(f"[+] HTML report written to {args.html}")

    threshold = Severity(args.fail_on)
    worst = max((f.severity for f in result.findings), default=Severity.INFO)
    if result.findings and worst.rank >= threshold.rank:
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
