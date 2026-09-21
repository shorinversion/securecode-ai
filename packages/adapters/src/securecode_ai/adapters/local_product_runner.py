"""Installed host-owned private-source Core composition.

The OS approval loader is the sole production authority entry point. This module
does not provision approval, promote evidence, start providers or scan worktree
file contents. Scripted peers can test plumbing, not provider qualification.
"""

from __future__ import annotations

from collections.abc import Callable

from securecode_ai.contracts import (
    RunExecutionIdentity,
)
from securecode_ai.core.reports import ReportFormat

from . import local_product_runner_execution as _execution_module
from .config import EffectiveConfiguration
from .git_snapshot import OfflineGitObjectReader as OfflineGitObjectReader
from .local_product_host import (
    LocalProductHost,
    verify_local_git_executable,
)
from .local_product_runner_config import (
    LocalProductCancelledError,
    LocalProductConfigurationError,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from .local_product_runner_config import _git as _git
from .local_product_runner_config import _pin as _pin
from .local_product_runner_config import _retain_evidence_graph as _retain_evidence_graph
from .local_product_runner_config import (
    resolve_local_product_configuration as resolve_local_product_configuration,
)

for _local_product_type in (
    LocalProductConfigurationError,
    LocalProductUnavailableError,
    LocalProductCancelledError,
    LocalProductSupersededError,
    LocalProductScanResult,
):
    _local_product_type.__module__ = __name__
del _local_product_type


def run_local_product_scan(
    *,
    host: LocalProductHost,
    target: str,
    report_format: ReportFormat,
    configuration: EffectiveConfiguration,
    execution_identity: RunExecutionIdentity | None = None,
    run_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> LocalProductScanResult:
    """Execute the installed actual Core composition on one immutable HEAD."""
    try:
        return _run_local_product_scan(
            host,
            target,
            report_format,
            configuration,
            execution_identity=execution_identity,
            run_id=run_id,
            cancelled=cancelled,
        )
    except (
        LocalProductConfigurationError,
        LocalProductUnavailableError,
        LocalProductCancelledError,
        LocalProductSupersededError,
        KeyboardInterrupt,
    ):
        raise
    except Exception:
        raise LocalProductUnavailableError() from None


def _run_local_product_scan(
    host: LocalProductHost,
    target: str,
    report_format: ReportFormat,
    configuration: EffectiveConfiguration,
    *,
    execution_identity: RunExecutionIdentity | None = None,
    run_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> LocalProductScanResult:
    return _execution_module._run_local_product_scan(
        host,
        target,
        report_format,
        configuration,
        execution_identity=execution_identity,
        run_id=run_id,
        cancelled=cancelled,
        git_verifier=verify_local_git_executable,
        git_command=_git,
        reader_factory=OfflineGitObjectReader,
    )


__all__ = [
    "LocalProductCancelledError",
    "LocalProductConfigurationError",
    "LocalProductScanResult",
    "LocalProductSupersededError",
    "LocalProductUnavailableError",
    "resolve_local_product_configuration",
    "run_local_product_scan",
]
