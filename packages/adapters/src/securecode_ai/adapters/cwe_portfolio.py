"""Conservative multi-language CWE portfolio facts.

This module consumes only a sealed ``SymbolIndex`` and structural parsers.  It
does not import, execute, retain, or expose analysed source.  The rules are
deliberately narrow: a result is a deterministic source-to-sink *fact*, not a
finding or verdict.
"""

from __future__ import annotations

from securecode_ai.core import SymbolIndex

from .cwe_portfolio_models import (
    DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS,
    CwePortfolioScanError,
    CwePortfolioScanErrorCode,
    CwePortfolioScanLimits,
    CwePortfolioScanResult,
    CwePortfolioSignal,
    portfolio_signals_to_raw_signals,
    scan_cwe_portfolio as _scan_cwe_portfolio,
)

for _portfolio_type in (
    CwePortfolioScanError,
    CwePortfolioScanLimits,
    CwePortfolioSignal,
    CwePortfolioScanResult,
):
    _portfolio_type.__module__ = __name__
del _portfolio_type


def scan_cwe_portfolio(
    symbol_index: SymbolIndex,
    *,
    limits: CwePortfolioScanLimits = DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS,
) -> CwePortfolioScanResult:
    """Run portfolio detectors and route CWE-862 through its bounded detectors."""
    result = _scan_cwe_portfolio(symbol_index, limits=limits)
    from .cwe_portfolio_helpers import _with_cwe862_detector_signals

    return _with_cwe862_detector_signals(
        result,
        symbol_index,
        limits=limits,
    )


__all__ = [
    "DEFAULT_CWE_PORTFOLIO_SCAN_LIMITS",
    "CwePortfolioScanError",
    "CwePortfolioScanErrorCode",
    "CwePortfolioScanLimits",
    "CwePortfolioScanResult",
    "CwePortfolioSignal",
    "portfolio_signals_to_raw_signals",
    "scan_cwe_portfolio",
]
