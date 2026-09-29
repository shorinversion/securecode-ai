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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from securecode_ai.contracts import (
    ArtifactRef,
    AuditRun,
    CandidateOrigin,
    ComponentPin,
    CoverageUnit,
    ModelCallStatus,
    ModelRequest,
    RunExecutionIdentity,
)
from securecode_ai.contracts.runtime import WorkflowControlState, WorkflowSnapshot
from securecode_ai.core.architect import ArchitectPatchResult
from securecode_ai.core.regression import SecurityRegressionDescriptor
from securecode_ai.core.repair_loop import RepairLoopReceipt
from securecode_ai.core.reports import (
    DeterministicReport,
)
from securecode_ai.core.root_cause import RootCauseRecord
from securecode_ai.core.validation import ValidationLadderResult

from .native_sources import NativeSourceCatalogue
from .product_execution import (
    ProductDeterministicExecution,
)
from .product_rule_catalogue import PRODUCT_RULE_CWE
from .product_runtime import ProductAuditorInvocationObservation
from .product_scanner import ProductDeterministicScanResult

if TYPE_CHECKING:
    from .product_review import ProductReviewResult
    from .product_scan import ProductCandidateFlow


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
    repair_requested_candidate_ids: tuple[str, ...] = ()
    repair_coverage_units: tuple[CoverageUnit, ...] = ()


@dataclass(frozen=True, slots=True)
class ProductRepairReceipt:
    """One repair attempt bundle bound to the originating product run.

    The values are metadata-only.  Patch bytes remain in the suggestion store,
    and the validation ladder remains the sole source of sandbox authority.
    ``security_test_*`` is optional because the current local repair path has a
    deterministic regression descriptor but no independent model-backed test
    generator.  The product audit layer turns that missing trusted receipt into
    incomplete coverage instead of manufacturing a completed stage.
    """

    finding_id: str
    candidate_id: str
    candidate_version: int
    run_id: str
    execution_identity_hash: str
    root_cause: RootCauseRecord
    regression: SecurityRegressionDescriptor
    architect: ArchitectPatchResult
    architect_model_result_sha256: str
    architect_model_call_status: ModelCallStatus
    architect_schema_valid_result: bool
    architect_receipt_id: str
    validation: ValidationLadderResult
    repair_loop: RepairLoopReceipt
    security_test_model_call_status: ModelCallStatus | None = None
    security_test_schema_valid_result: bool | None = None
    security_test_receipt_id: str | None = None
    security_test_output_sha256: str | None = None

    def __post_init__(self) -> None:
        values = (
            self.finding_id,
            self.candidate_id,
            self.run_id,
            self.execution_identity_hash,
            self.architect_model_result_sha256,
            self.architect_receipt_id,
        )
        if (
            any(type(value) is not str or not value for value in values)
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.root_cause) is not RootCauseRecord
            or type(self.regression) is not SecurityRegressionDescriptor
            or type(self.architect) is not ArchitectPatchResult
            or type(self.architect_model_call_status) is not ModelCallStatus
            or type(self.architect_schema_valid_result) is not bool
            or self.architect_model_call_status is not ModelCallStatus.SUCCEEDED
            or self.architect_schema_valid_result is not True
            or type(self.validation) is not ValidationLadderResult
            or type(self.repair_loop) is not RepairLoopReceipt
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in (self.architect_model_result_sha256,)
            )
            or self.root_cause.finding_id != self.finding_id
            or self.root_cause.candidate_id != self.candidate_id
            or self.root_cause.candidate_version != self.candidate_version
            or self.regression.finding_id != self.finding_id
            or self.regression.root_cause_id != self.root_cause.record_id
            or self.regression.tenant_id != self.root_cause.tenant_id
            or self.regression.repository_id != self.root_cause.repository_id
            or self.regression.vulnerable_head_sha != self.root_cause.head_sha
            or self.architect.patch_candidate.finding_id != self.finding_id
            or self.architect.patch_candidate.repository_revision.tenant_id
            != self.root_cause.tenant_id
            or self.architect.patch_candidate.repository_revision.repository_id
            != self.root_cause.repository_id
            or self.architect.patch_candidate.repository_revision.head_sha
            != self.root_cause.head_sha
            or self.architect.rationale.finding_id != self.finding_id
            or self.architect.rationale.root_cause_id != self.root_cause.record_id
            or self.architect.rationale.regression_descriptor_id != self.regression.descriptor_id
            or self.validation.validation.patch_id != self.architect.patch_candidate.patch_id
            or self.validation.validation.tenant_id != self.root_cause.tenant_id
            # Validation evaluates the patched head, never the vulnerable one
            # (same invariant as core.diff_review / core.patch_status_helpers).
            or self.validation.validation.head_sha == self.regression.vulnerable_head_sha
            or not self.repair_loop.attempts
            or self.repair_loop.attempts[-1].patch_id != self.architect.patch_candidate.patch_id
            or self.repair_loop.attempts[-1].validation_id
            != self.validation.validation.validation_id
            or self.repair_loop.attempts[-1].validation_result_sha256
            != self.validation.validation.result_sha256
        ):
            raise ValueError("product repair receipt is not identity-bound")
        security_fields = (
            self.security_test_model_call_status,
            self.security_test_schema_valid_result,
            self.security_test_receipt_id,
            self.security_test_output_sha256,
        )
        if all(value is None for value in security_fields):
            return
        if (
            type(self.security_test_model_call_status) is not ModelCallStatus
            or self.security_test_schema_valid_result is not True
            or type(self.security_test_receipt_id) is not str
            or not self.security_test_receipt_id
            or type(self.security_test_output_sha256) is not str
            or len(self.security_test_output_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.security_test_output_sha256
            )
        ):
            raise ValueError("product security-test receipt is incomplete")


@dataclass(frozen=True, slots=True)
class ProductAuditComposition:
    """One exact Core run and reports rendered from that same run."""

    run: AuditRun
    report: DeterministicReport
    json_report: bytes
    html_report: bytes
    preliminary_json_report: bytes | None = None
    preliminary_html_report: bytes | None = None
    flow: ProductCandidateFlow | None = field(default=None, repr=False, compare=False)
    review: ProductReviewResult | None = field(default=None, repr=False, compare=False)
    host_inputs: ProductAuditHostInputs | None = field(default=None, repr=False, compare=False)


class _AuditObstacle(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(code)


_PRODUCT_CWE_RULES = {
    cwe_id: tuple(
        sorted(rule_id for rule_id, mapped_cwe in PRODUCT_RULE_CWE.items() if mapped_cwe == cwe_id)
    )
    for cwe_id in sorted(set(PRODUCT_RULE_CWE.values()) - {"CWE-89"})
}
