"""Human-friendly coloured console output."""

from __future__ import annotations

from colorama import Fore, Style, init as colorama_init

from webscan.core.engine import ScanResult
from webscan.core.finding import Severity

colorama_init()

SEVERITY_COLORS = {
    Severity.CRITICAL: Fore.MAGENTA,
    Severity.HIGH: Fore.RED,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE,
}


class ConsoleReporter:
    """Prints a readable, colour-coded summary to stdout."""

    def __init__(self, show_info: bool = True) -> None:
        self.show_info = show_info

    def render(self, result: ScanResult) -> None:
        print(f"\n{Style.BRIGHT}Target:{Style.RESET_ALL} {result.target}")
        print(
            f"{Style.BRIGHT}Modules:{Style.RESET_ALL} {', '.join(result.modules_run) or 'none'}"
        )
        print(f"{Style.BRIGHT}Duration:{Style.RESET_ALL} {result.duration}s\n")

        findings = result.sorted_findings()
        if not self.show_info:
            findings = [f for f in findings if f.severity != Severity.INFO]

        if not findings:
            print(f"{Fore.GREEN}No findings to report.{Style.RESET_ALL}")
        else:
            for f in findings:
                color = SEVERITY_COLORS.get(f.severity, Fore.WHITE)
                tag = f"[{f.severity.value.upper()}]"
                print(f"{color}{Style.BRIGHT}{tag:<11}{Style.RESET_ALL}{color}{f.title}{Style.RESET_ALL}")
                print(f"  {Style.DIM}module:{Style.RESET_ALL} {f.module}   {Style.DIM}target:{Style.RESET_ALL} {f.target}")
                print(f"  {f.description}")
                if f.evidence:
                    print(f"  {Style.DIM}evidence:{Style.RESET_ALL} {f.evidence}")
                if f.remediation:
                    print(f"  {Style.DIM}fix:{Style.RESET_ALL} {f.remediation}")
                print()

        self._summary(result)

    def _summary(self, result: ScanResult) -> None:
        counts = result.counts()
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            color = SEVERITY_COLORS[sev]
            parts.append(f"{color}{sev.value}={counts[sev.value]}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}Summary:{Style.RESET_ALL} " + "  ".join(parts))
        if result.errors:
            print(f"{Fore.YELLOW}Module errors: {len(result.errors)}{Style.RESET_ALL}")
