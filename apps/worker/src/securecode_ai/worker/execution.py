"""Actual product-runner composition used by the connected worker."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import cast

from securecode_ai.adapters.local_product_host import (
    LocalProductHostError,
    load_local_product_host,
    verify_local_git_executable,
)
from securecode_ai.adapters.local_product_runner import (
    resolve_local_product_configuration,
    run_local_product_scan,
)
from securecode_ai.adapters.local_product_runner_config import (
    LocalProductCancelledError,
    LocalProductConfigurationError,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from securecode_ai.contracts import ArtifactRef, AuditRunOutcome, DataClass, ProviderKind
from securecode_ai.core.reports import ReportFormat

from .protocol import (
    WorkerArtifact,
    WorkerCommand,
    WorkerContributionTrust,
    WorkerFinding,
    WorkerFindingLocation,
    WorkerJob,
)


class ProductExecutionError(RuntimeError):
    """Closed product execution failure without source or secret text."""


class ProductIdentityMismatch(ProductExecutionError):
    pass


class ProductCancelled(ProductExecutionError):
    pass


class ProductSuperseded(ProductExecutionError):
    pass


class ExecutionControl:
    """Thread-safe cooperative stop signal for one active product execution."""

    def __init__(self) -> None:
        self._command: WorkerCommand | None = None
        self._lock = Lock()

    def request(self, command: WorkerCommand) -> None:
        if command not in {WorkerCommand.CANCEL, WorkerCommand.SUPERSEDE}:
            raise ValueError("worker stop command is invalid")
        with self._lock:
            if self._command is None or command is WorkerCommand.SUPERSEDE:
                self._command = command

    def checkpoint(self, scan: LocalProductScanResult | None = None) -> None:
        with self._lock:
            command = self._command
        if command is None:
            return
        if scan is not None:
            with suppress(Exception):
                scan.cancel()
        if command is WorkerCommand.SUPERSEDE:
            raise ProductSuperseded("product revision was superseded")
        raise ProductCancelled("product run was cancelled")

    def cancelled(self) -> bool:
        with self._lock:
            return self._command is not None


@dataclass(frozen=True, slots=True)
class WorkerExecutionResult:
    outcome: str
    artifacts: tuple[WorkerArtifact, ...]
    findings: tuple[WorkerFinding, ...]
    scan: LocalProductScanResult

    def cancel(self) -> None:
        self.scan.cancel()


class ProductExecutor:
    """Run the installed host-authorized product against one fixed checkout."""

    def __init__(self, *, target: Path, environment: Mapping[str, str]) -> None:
        if not target.is_absolute() or not target.is_dir() or target.is_symlink():
            raise ValueError("worker target is invalid")
        self._target = target
        self._environment = dict(environment)

    def execute(
        self,
        job: WorkerJob,
        *,
        control: ExecutionControl | None = None,
    ) -> WorkerExecutionResult:
        expected = job.execution_identity
        execution_control = control or ExecutionControl()
        try:
            execution_control.checkpoint()
            host = load_local_product_host()
            execution_control.checkpoint()
            executable = verify_local_git_executable(
                host.artifact_manifest.get("git_executable_sha256", "")
            )
            _require_exact_checkout(
                self._target,
                executable,
                expected.repository_revision.head_sha,
            )
            execution_control.checkpoint()
            environment = _contribution_environment(job, self._environment)
            configuration = resolve_local_product_configuration(
                host,
                environment=environment,
            )
            _require_contribution_provider(job, configuration.provider_profile.provider_kind)
            execution_control.checkpoint()
            scan = run_local_product_scan(
                host=host,
                target=str(self._target),
                report_format=ReportFormat.JSON,
                configuration=configuration,
                execution_identity=expected,
                run_id=job.run_id,
                cancelled=execution_control.cancelled,
            )
            execution_control.checkpoint(scan)
            actual = scan.composition.run.execution_identity
            if actual != expected:
                scan.cancel()
                raise ProductIdentityMismatch("product execution identity does not match the lease")
            if scan.composition.run.current_head_sha != expected.repository_revision.head_sha:
                scan.cancel()
                raise ProductSuperseded("product revision was superseded")
            scan.require_publication()
            artifacts = _artifacts(scan)
            graph_reference = next(
                artifact.reference for artifact in artifacts if artifact.purpose == "evidence-graph"
            )
            return WorkerExecutionResult(
                outcome=_worker_outcome(scan.composition.run.audit_outcome),
                artifacts=artifacts,
                findings=_findings(scan, graph_reference),
                scan=scan,
            )
        except ProductExecutionError:
            raise
        except LocalProductCancelledError:
            execution_control.checkpoint()
            raise ProductCancelled("product run was cancelled") from None
        except LocalProductSupersededError:
            raise ProductSuperseded("product revision was superseded") from None
        except (
            LocalProductConfigurationError,
            LocalProductHostError,
            LocalProductUnavailableError,
            OSError,
            subprocess.SubprocessError,
            ValueError,
        ):
            raise ProductExecutionError("product execution failed") from None
        except Exception:
            raise ProductExecutionError("product execution failed") from None


def _require_exact_checkout(target: Path, executable: Path, expected_head: str) -> None:
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise ProductExecutionError("approved Git executable is unavailable")
    environment = {
        key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP") if key in os.environ
    }
    environment.update(
        GIT_ALLOW_PROTOCOL="",
        GIT_CONFIG_COUNT="0",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    command = [
        str(executable),
        "--no-pager",
        "--no-replace-objects",
        "--no-optional-locks",
        "-C",
        str(target),
    ]
    try:
        top = _git_output([*command, "rev-parse", "--show-toplevel"], environment)
        head = _git_output([*command, "rev-parse", "--verify", "HEAD"], environment)
        details = target.stat(follow_symlinks=False)
    except (OSError, subprocess.SubprocessError):
        raise ProductExecutionError("worker checkout verification failed") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or Path(top).resolve() != target.resolve()
        or head != expected_head
    ):
        raise ProductIdentityMismatch("worker checkout does not match the lease")


def _git_output(command: list[str], environment: Mapping[str, str]) -> str:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(environment),
        timeout=10,
        check=False,
        creationflags=_subprocess_creation_flags(),
    )
    if completed.returncode or len(completed.stdout) > 65536:
        raise ProductExecutionError("worker checkout verification failed")
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ProductExecutionError("worker checkout verification failed") from None


def _subprocess_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess).get("CREATE_NO_WINDOW", 0))


def _is_credential_name(name: str) -> bool:
    normalized = name.upper()
    return any(
        marker in normalized for marker in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    )


def _contribution_environment(job: WorkerJob, environment: Mapping[str, str]) -> dict[str, str]:
    restricted = job.contribution_trust in {
        WorkerContributionTrust.UNTRUSTED_FORK,
        WorkerContributionTrust.UNTRUSTED_SAME_REPOSITORY,
        WorkerContributionTrust.UNKNOWN,
    }
    if not restricted:
        return dict(environment)
    return {key: value for key, value in environment.items() if not _is_credential_name(key)}


def _require_contribution_provider(job: WorkerJob, provider_kind: ProviderKind) -> None:
    restricted = job.contribution_trust in {
        WorkerContributionTrust.UNTRUSTED_FORK,
        WorkerContributionTrust.UNTRUSTED_SAME_REPOSITORY,
        WorkerContributionTrust.UNKNOWN,
    }
    if restricted and provider_kind not in {
        ProviderKind.FAKE,
        ProviderKind.OPENAI_COMPATIBLE_LOCAL,
    }:
        raise ProductExecutionError("untrusted contribution requires a local provider")


def _artifacts(scan: LocalProductScanResult) -> tuple[WorkerArtifact, ...]:
    run = scan.composition.run
    tenant_id = run.execution_identity.repository_revision.tenant_id
    return (
        _artifact(
            tenant_id=tenant_id,
            purpose="audit-report",
            prefix="worker-report",
            content=scan.rendered,
        ),
        _artifact(
            tenant_id=tenant_id,
            purpose="sarif-report",
            prefix="worker-sarif",
            content=scan.sarif_rendered,
        ),
        _artifact(
            tenant_id=tenant_id,
            purpose="evidence-graph",
            prefix="worker-graph",
            content=scan.graph_artifact,
        ),
        _artifact(
            tenant_id=tenant_id,
            purpose="audit-run",
            prefix="worker-run",
            content=json.dumps(
                run.model_dump(mode="json"),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        ),
    )


def _findings(
    scan: LocalProductScanResult, graph_reference: ArtifactRef
) -> tuple[WorkerFinding, ...]:
    report = scan.composition.report
    revision = report.run.execution_identity.repository_revision
    graph_sha256 = hashlib.sha256(scan.graph_artifact).hexdigest()
    if (
        type(graph_reference) is not ArtifactRef
        or graph_reference.tenant_id != revision.tenant_id
        or graph_reference.content_sha256 != graph_sha256
        or graph_reference.size_bytes != len(scan.graph_artifact)
        or graph_reference.data_class is not DataClass.CONFIDENTIAL_SECURITY
    ):
        raise ProductIdentityMismatch("worker graph artifact does not match the product run")
    values: list[WorkerFinding] = []
    for item in report.findings:
        finding = item.finding
        reference = finding.evidence_graph_ref
        if (
            finding.repository_revision != revision
            or reference.tenant_id != revision.tenant_id
            or reference.content_sha256 != graph_sha256
        ):
            raise ProductIdentityMismatch("finding evidence does not match the product run")
        values.append(
            WorkerFinding(
                finding_id=finding.finding_id,
                revision_sha=finding.repository_revision.head_sha,
                cwe_id=finding.cwe_id,
                severity=item.classification.severity.value,
                confidence=item.classification.confidence.value,
                verdict=finding.finding_verdict.value,
                blocking=finding.blocking,
                locations=tuple(
                    WorkerFindingLocation(
                        path=location.path,
                        start_line=location.start.line,
                        end_line=location.end.line,
                    )
                    for location in finding.locations
                ),
                evidence_graph_ref=graph_reference,
                root_cause_fingerprint=finding.root_cause_fingerprint,
            )
        )
    if tuple(value.finding_id for value in values) != tuple(
        sorted(value.finding_id for value in values)
    ):
        raise ProductExecutionError("product findings are not canonical")
    return tuple(values)


def _artifact(*, tenant_id: str, purpose: str, prefix: str, content: bytes) -> WorkerArtifact:
    digest = hashlib.sha256(content).hexdigest()
    reference = ArtifactRef(
        schema_version="0.2.0",
        tenant_id=tenant_id,
        content_id=f"{prefix}-{digest[:32]}",
        content_sha256=digest,
        size_bytes=len(content),
        data_class=DataClass.CONFIDENTIAL_SECURITY,
    )
    return WorkerArtifact(reference=reference, purpose=purpose, content=content)


def _worker_outcome(outcome: AuditRunOutcome) -> str:
    if outcome is AuditRunOutcome.ERROR:
        return "INDETERMINATE"
    if outcome.value in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}:
        return outcome.value
    raise ProductExecutionError("product outcome is invalid")


__all__ = [
    "ExecutionControl",
    "ProductCancelled",
    "ProductExecutionError",
    "ProductExecutor",
    "ProductIdentityMismatch",
    "ProductSuperseded",
    "WorkerExecutionResult",
]
