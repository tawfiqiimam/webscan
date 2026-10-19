"""webscan — a professional, modular web vulnerability scanner.

For authorized security testing only.
"""

__version__ = "1.0.0"
__author__ = "Tawfiq Imam"

from webscan.core.finding import Finding, Severity

__all__ = ["Finding", "Severity", "__version__"]
