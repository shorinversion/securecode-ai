"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from securecode_ai.contracts import (
    ArtifactRef,
    AuditRun,
    CandidateOrigin,
    ComponentPin,
    ModelRequest,
    RunExecutionIdentity,
)
from securecode_ai.contracts.runtime import WorkflowControlState, WorkflowSnapshot
from securecode_ai.core.reports import (
    DeterministicReport,
)

from .native_sources import NativeSourceCatalogue
from .product_execution import (
    ProductDeterministicExecution,
)
from .product_runtime import ProductAuditorInvocationObservation
from .product_scanner import ProductDeterministicScanResult


@dataclass(frozen=True, slots=True)
class ProductAuditObstacle:
    """A source-free incompatibility that prevents a trustworthy public run."""

    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class ProductDiscoveryCandidateMapping:
    """Read-only provenance from an immutable discovery ID to current graph ID."""

    receipt_candidate_id: str
    current_candidate_id: str
    current_candidate_version: int
    current_origin: CandidateOrigin


@dataclass(frozen=True, slots=True)
class ProductAuditFindingMetadata:
    """Host-owned rule metadata required to render an actual blocking finding."""

    candidate_id: str
    candidate_version: int
    finding_id: str
    cwe_id: str
    evidence_graph_ref: ArtifactRef
    rule_id: str | None = None
    root_cause_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class ProductAuditStateObservation:
    """Host-owned current state, bound to the exact execution."""

    run_id: str
    execution_identity_hash: str
    current_head_sha: str
    cancelled: bool
    reporting_allowed: bool


class ProductAuditStateProbe(Protocol):
    def observe(
        self, *, run_id: str, execution_identity: RunExecutionIdentity
    ) -> ProductAuditStateObservation: ...


class GitProductAuditStateProbe:
    """Read actual Git HEAD and typed host-owned worker/control-plane ports.

    Checkout, executable and callbacks are host capabilities, never MR inputs.
    This adapter does not mutate refs, read sources or execute repository hooks.
    The snapshot callback must read the current authoritative worker snapshot;
    persistence/freshness of that port belongs to the control plane.
    """

    def __init__(
        self,
        *,
        checkout: Path,
        git_executable: Path,
        snapshot_for: Callable[[str, RunExecutionIdentity], WorkflowSnapshot],
        reporting_policy: Callable[[WorkflowSnapshot], bool],
    ):
        if (
            not checkout.is_absolute()
            or not checkout.is_dir()
            or checkout.is_symlink()
            or not git_executable.is_absolute()
            or not git_executable.is_file()
            or not callable(snapshot_for)
            or not callable(reporting_policy)
        ):
            raise ValueError("product host state configuration invalid")
        self._checkout = checkout
        self._git = git_executable
        self._snapshot_for = snapshot_for
        self._reporting_policy = reporting_policy

    def observe(
        self, *, run_id: str, execution_identity: RunExecutionIdentity
    ) -> ProductAuditStateObservation:
        env = {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
            if name in os.environ
        }
        env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_SYSTEM=os.devnull,
            GIT_CONFIG_COUNT="0",
            GIT_NO_REPLACE_OBJECTS="1",
            GIT_TERMINAL_PROMPT="0",
            GIT_OPTIONAL_LOCKS="0",
        )
        failed = False
        try:
            result = subprocess.run(
                [
                    str(self._git),
                    "--no-pager",
                    "--no-replace-objects",
                    "--no-optional-locks",
                    "-C",
                    str(self._checkout),
                    "rev-parse",
                    "--verify",
                    "HEAD",
                ],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            head = result.stdout.decode("ascii").strip()
            if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", head) is None:
                raise ValueError
            supplied = self._snapshot_for(run_id, execution_identity)
            if type(supplied) is not WorkflowSnapshot:
                raise ValueError
            snapshot = WorkflowSnapshot.model_validate_json(supplied.model_dump_json())
            if (
                snapshot.run_id != run_id
                or snapshot.execution_identity != execution_identity
                or snapshot.tenant_id != execution_identity.repository_revision.tenant_id
            ):
                raise ValueError
            if snapshot.control_state is WorkflowControlState.SUPERSEDED:
                raise ValueError
            allowed = self._reporting_policy(snapshot)
            if type(allowed) is not bool:
                raise ValueError
        except Exception:
            failed = True
        if failed:
            raise ValueError("PRODUCT_HOST_STATE_READ_FAILED") from None
        return ProductAuditStateObservation(
            run_id,
            execution_identity.execution_identity_hash,
            head,
            snapshot.control_state is WorkflowControlState.CANCELLED,
            allowed,
        )


@dataclass(frozen=True, slots=True)
class ProductAuditHostInputs:
    """Host-owned execution selectors and retained invocation observations."""

    run_id: str
    execution_identity: RunExecutionIdentity
    discovery_request: ModelRequest
    auditor: ComponentPin
    source_catalogue: NativeSourceCatalogue
    created_at: datetime
    completed_at: datetime
    auditor_observations: tuple[ProductAuditorInvocationObservation, ...] = ()
    deterministic_scan: ProductDeterministicScanResult | None = None
    finding_metadata: tuple[ProductAuditFindingMetadata, ...] = ()
    report_tools: tuple[ComponentPin, ...] = ()
    deterministic_execution: ProductDeterministicExecution | None = None
    state_probe: ProductAuditStateProbe | None = None
    operation: str = "scan"


@dataclass(frozen=True, slots=True)
class ProductAuditComposition:
    """One exact Core run and reports rendered from that same run."""

    run: AuditRun
    report: DeterministicReport
    json_report: bytes
    html_report: bytes
    preliminary_json_report: bytes | None = None
    preliminary_html_report: bytes | None = None


class _AuditObstacle(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)


_PRODUCT_CWE_RULES = {
    "CWE-22": "portfolio-cwe-22",
    "CWE-78": "portfolio-cwe-78",
    "CWE-862": "portfolio-cwe-862",
    "CWE-918": "portfolio-cwe-918",
}
