"""Bounded JavaScript, TypeScript, and Go CWE-89 scanner facts.

The adapter consumes a sealed CST index and never executes, imports, or reads
the analysed program.  It intentionally emits deterministic source-to-sink
facts only; normalization, interpretation, verdict, and report construction
remain owned by the existing common Core pipeline.
"""

from __future__ import annotations

from .cwe89_multilanguage_models import (
    DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS,
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanErrorCode,
    MultilanguageCwe89ScanLimits,
    MultilanguageCwe89ScanResult,
    MultilanguageCwe89Signal,
)
from .cwe89_multilanguage_scanner import (
    scan_go_cwe89,
    scan_javascript_cwe89,
    scan_typescript_cwe89,
)
from .cwe89_multilanguage_utilities import multilanguage_cwe89_signals_to_raw_signals

for _cwe_type in (
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanLimits,
    MultilanguageCwe89Signal,
    MultilanguageCwe89ScanResult,
):
    _cwe_type.__module__ = __name__
del _cwe_type
__all__ = [
    "DEFAULT_MULTILANGUAGE_CWE89_SCAN_LIMITS",
    "MultilanguageCwe89ScanError",
    "MultilanguageCwe89ScanErrorCode",
    "MultilanguageCwe89ScanLimits",
    "MultilanguageCwe89ScanResult",
    "MultilanguageCwe89Signal",
    "multilanguage_cwe89_signals_to_raw_signals",
    "scan_go_cwe89",
    "scan_javascript_cwe89",
    "scan_typescript_cwe89",
]
