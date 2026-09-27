"""Actual product-runner composition used by the connected worker."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import signal
import stat
import subprocess
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic
from typing import cast

from securecode_ai.adapters.dependency_scanning import ApprovedOsvScanner
from securecode_ai.adapters.local_product_host import (
    LocalProductHost,
    LocalProductHostError,
    load_local_product_host,
    verify_local_git_executable,
)
from securecode_ai.adapters.local_product_runner import (
    resolve_local_product_configuration,
    run_local_product_repair,
    run_local_product_scan,
)
from securecode_ai.adapters.local_patch_status import LocalPatchStatusStore
from securecode_ai.adapters.patch_artifact import (
    PatchArtifactError,
    PatchArtifactStore,
    default_patch_artifact_root,
)
from securecode_ai.adapters.product_provider_runtime import (
    ProductProviderConfigurationError,
    ProductProviderRuntime,
    load_product_provider_runtime,
)
from securecode_ai.adapters.local_product_runner_config import (
    LocalProductCancelledError,
    LocalProductConfigurationError,
    LocalProductRepairResult,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from securecode_ai.contracts import (
    ArtifactRef,
    AuditRunOutcome,
    DataClass,
    ModelUsage,
    ProviderKind,
)
from securecode_ai.adapters.remote_provider_budget import RemoteProviderCostReceipt
from securecode_ai.core.reports import ReportFormat

from .protocol import (
    WorkerArtifact,
    WorkerCommand,
    WorkerContributionTrust,
    WorkerFinding,
    WorkerFindingLocation,
    WorkerJob,
    WorkerOperation,
    WorkerRepairPatchBinding,
)

_CANCEL_CALLBACK_TIMEOUT_SECONDS = 5.0
_CANCEL_SETUP_TIMEOUT_SECONDS = 5.0
_CHILD_EXIT_TIMEOUT_SECONDS = 2.0


class ProductExecutionError(RuntimeError):
    """Closed product execution failure without source or secret text."""


class ProductIdentityMismatch(ProductExecutionError):
    pass


class ProductCancelled(ProductExecutionError):
    pass


class ProductSuperseded(ProductExecutionError):
    pass


class ResourceLimitExceeded(ProductExecutionError):
    pass


class ExecutionControl:
    """Thread-safe cooperative stop signal for one active product execution."""

    def __init__(self) -> None:
        self._command: WorkerCommand | None = None
        self._lock = Lock()
        self._cancel_callbacks: list[Callable[[], None]] = []
        self._cancel_callback_dispatched = False
        self._cancel_callback_done = Event()
        self._cancel_callback_batches = 0
        self._cancel_callback_failed = False
        self._execution_active = False
        self._execution_started = False
        self._cancel_setup_done = Event()
        self._cancel_setup_done.set()

    def begin_execution(self) -> None:
        with self._lock:
            if self._execution_started:
                raise ProductExecutionError("worker execution control was reused")
            self._execution_started = True
            self._execution_active = True
            if not self._cancel_callbacks:
                self._cancel_setup_done.clear()

    def finish_execution(self) -> None:
        with self._lock:
            self._execution_active = False
            self._cancel_setup_done.set()

    def register_cancel_callback(self, callback: Callable[[], None]) -> None:
        if not callable(callback):
            raise ValueError("worker cancellation callback is invalid")
        dispatch: tuple[Callable[[], None], ...] = ()
        with self._lock:
            self._cancel_callbacks.append(callback)
            self._cancel_setup_done.set()
            if self._command is not None:
                if not self._cancel_callback_dispatched:
                    self._cancel_callback_dispatched = True
                    dispatch = tuple(self._cancel_callbacks)
                else:
                    dispatch = (callback,)
                self._begin_cancel_callback_batch_locked()
        if dispatch:
            self._invoke_cancel_callbacks(dispatch)

    def request(self, command: WorkerCommand) -> None:
        if command not in {WorkerCommand.CANCEL, WorkerCommand.SUPERSEDE}:
            raise ValueError("worker stop command is invalid")
        with self._lock:
            if self._command is None or command is WorkerCommand.SUPERSEDE:
                self._command = command
        self._await_cancel_cleanup()

    def _await_cancel_cleanup(self) -> None:
        while True:
            callbacks: tuple[Callable[[], None], ...] = ()
            wait_for_callback = False
            wait_for_setup = False
            with self._lock:
                if self._cancel_callback_failed:
                    raise ProductExecutionError("worker cancellation cleanup failed")
                if self._command is None:
                    return
                if not self._cancel_callbacks:
                    wait_for_setup = (
                        self._execution_active and not self._cancel_setup_done.is_set()
                    )
                elif not self._cancel_callback_dispatched:
                    self._cancel_callback_dispatched = True
                    callbacks = tuple(self._cancel_callbacks)
                    self._begin_cancel_callback_batch_locked()
                else:
                    wait_for_callback = True
            if wait_for_setup:
                if not self._cancel_setup_done.wait(_CANCEL_SETUP_TIMEOUT_SECONDS):
                    with self._lock:
                        self._cancel_callback_failed = True
                    raise ProductExecutionError("worker cancellation cleanup was not resolved")
                continue
            if callbacks:
                self._invoke_cancel_callbacks(callbacks)
            elif wait_for_callback:
                self._wait_for_cancel_callback()
            return

    def _invoke_cancel_callbacks(self, callbacks: tuple[Callable[[], None], ...]) -> None:
        def invoke() -> None:
            try:
                for callback in callbacks:
                    callback()
            except Exception:
                with self._lock:
                    self._cancel_callback_failed = True
            finally:
                with self._lock:
                    self._cancel_callback_batches -= 1
                    if self._cancel_callback_batches == 0:
                        self._cancel_callback_done.set()

        Thread(target=invoke, name="securecode-worker-cancel", daemon=True).start()
        self._wait_for_cancel_callback()

    def _wait_for_cancel_callback(self) -> None:
        with self._lock:
            if self._cancel_callback_failed:
                raise ProductExecutionError("worker cancellation cleanup failed")
        if not self._cancel_callback_done.wait(_CANCEL_CALLBACK_TIMEOUT_SECONDS):
            with self._lock:
                self._cancel_callback_failed = True
        with self._lock:
            failed = self._cancel_callback_failed
        if failed:
            raise ProductExecutionError("worker cancellation cleanup failed")

    def _begin_cancel_callback_batch_locked(self) -> None:
        self._cancel_callback_batches += 1
        self._cancel_callback_done.clear()

    def checkpoint(self) -> None:
        if self.cancelled():
            with self._lock:
                command = self._command
                cleanup_failed = self._cancel_callback_failed
            if cleanup_failed:
                raise ProductExecutionError("worker cancellation cleanup failed")
        else:
            return
        if command is WorkerCommand.SUPERSEDE:
            raise ProductSuperseded("product revision was superseded")
        raise ProductCancelled("product run was cancelled")

    def cancelled(self) -> bool:
        dispatch: tuple[Callable[[], None], ...] = ()
        wait_for_callback = False
        with self._lock:
            requested = self._command is not None
            if requested and self._cancel_callbacks and not self._cancel_callback_dispatched:
                self._cancel_callback_dispatched = True
                dispatch = tuple(self._cancel_callbacks)
                self._begin_cancel_callback_batch_locked()
            elif requested and self._cancel_callbacks and not self._cancel_callback_failed:
                wait_for_callback = True
        if dispatch:
            self._invoke_cancel_callbacks(dispatch)
        elif wait_for_callback:
            self._wait_for_cancel_callback()
        return requested


@dataclass(frozen=True, slots=True)
class WorkerExecutionResult:
    outcome: str
    artifacts: tuple[WorkerArtifact, ...]
    findings: tuple[WorkerFinding, ...]
    scan: LocalProductScanResult
    repair: LocalProductRepairResult | None = None

    def require_publication(self) -> None:
        """Revalidate the leased checkout and reporting policy before publication."""

        self.scan.require_publication()

    def cancel(self) -> None:
        self.scan.cancel()


_SAFE_UNTRUSTED_CONFIGURATION_ENVIRONMENT = frozenset(
    {
        "SECURECODE_PROVIDER_PROFILE",
        "SECURECODE_POLICY_PROFILE",
        "SECURECODE_EGRESS_PROFILE",
        "SECURECODE_AI_VALIDATION_IMAGE",
        "SECURECODE_AI_VALIDATOR_MODE",
        "SECURECODE_AI_VALIDATOR_SOCKET",
        "SECURECODE_AI_VALIDATOR_BUNDLE_ROOT",
        "SECURECODE_AI_VALIDATOR_IDENTITY",
        "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET",
        "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET_UID",
        "SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE_SHA256",
    }
)


class ProductExecutor:
    """Run the installed host-authorized product against one fixed checkout."""

    def __init__(
        self,
        *,
        target: Path,
        environment: Mapping[str, str],
        dependency_scanner_for: Callable[[WorkerJob], ApprovedOsvScanner] | None = None,
    ) -> None:
        if not target.is_absolute() or not target.is_dir() or target.is_symlink():
            raise ValueError("worker target is invalid")
        if dependency_scanner_for is not None and not callable(dependency_scanner_for):
            raise ValueError("worker dependency scanner factory is invalid")
        self._target = target
        self._environment = dict(environment)
        self._dependency_scanner_for = dependency_scanner_for

    def execute(
        self,
        job: WorkerJob,
        *,
        control: ExecutionControl | None = None,
        usage_observer: Callable[[ModelUsage], None] | None = None,
        cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    ) -> WorkerExecutionResult:
        if job.resource_budget is None:
            raise ProductExecutionError("worker resource budget unavailable")
        expected = job.execution_identity
        execution_control = control or ExecutionControl()
        execution_control.begin_execution()
        scan: LocalProductScanResult | None = None
        scan_transferred = False
        provider_runtime: ProductProviderRuntime | None = None
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
                control=execution_control,
            )
            execution_control.checkpoint()
            environment = _contribution_environment(job, self._environment)
            if _remote_provider_requested(expected, host, environment):
                try:
                    provider_runtime = load_product_provider_runtime(
                        profile_path=environment.get("SECURECODE_REMOTE_PROFILE_FILE", ""),
                        policy_path=environment.get("SECURECODE_REMOTE_POLICY_FILE", ""),
                        environment=environment,
                        tenant_id=expected.repository_revision.tenant_id,
                        expected_profile_sha256=expected.provider_profile.content_sha256,
                        expected_policy_sha256=expected.policy.content_sha256,
                        expected_egress_sha256=expected.egress_profile.content_sha256,
                        expected_configuration_sha256=expected.configuration.content_sha256,
                    )
                except ProductProviderConfigurationError:
                    raise ProductExecutionError("worker remote provider configuration failed") from None
                configuration = provider_runtime.configuration
            else:
                configuration = resolve_local_product_configuration(
                    host,
                    environment=environment,
                )
            operation = _requested_operation(job)
            if provider_runtime is not None and operation is WorkerOperation.REPAIR:
                try:
                    provider_runtime.repair()
                except ProductProviderConfigurationError:
                    raise ProductExecutionError(
                        "worker remote repair configuration failed"
                    ) from None
            _require_contribution_provider(job, configuration.provider_profile.provider_kind)
            dependency_scanner = None
            if self._dependency_scanner_for is not None:
                dependency_scanner = self._dependency_scanner_for(job)
            if dependency_scanner is None and self._dependency_scanner_for is not None:
                raise ProductExecutionError("worker dependency scanner is unavailable")
            if dependency_scanner is not None and not callable(
                getattr(dependency_scanner, "query_batch", None)
            ):
                raise ProductExecutionError("worker dependency scanner is invalid")
            execution_control.checkpoint()
            scan = run_local_product_scan(
                host=host,
                target=str(self._target),
                report_format=ReportFormat.JSON,
                configuration=configuration,
                execution_identity=expected,
                run_id=job.run_id,
                cancelled=execution_control.cancelled,
                on_cancel=execution_control.register_cancel_callback,
                usage_observer=usage_observer,
                cost_observer=cost_observer,
                dependency_scanner=dependency_scanner,
                provider_runtime=provider_runtime,
            )
            execution_control.checkpoint()
            actual = scan.composition.run.execution_identity
            if actual != expected:
                raise ProductIdentityMismatch("product execution identity does not match the lease")
            if scan.composition.run.current_head_sha != expected.repository_revision.head_sha:
                raise ProductSuperseded("product revision was superseded")
            scan.require_publication()
            repair = None
            if operation is WorkerOperation.REPAIR:
                execution_control.checkpoint()
                repair = run_local_product_repair(
                    target=str(self._target),
                    host=host,
                    scan_result=scan,
                    environment=environment,
                    cancelled=execution_control.cancelled,
                    on_cancel=execution_control.register_cancel_callback,
                    usage_observer=usage_observer,
                    cost_observer=cost_observer,
                    provider_runtime=provider_runtime,
                )
                # A repair sidecar is allowed to leave only a suggestion
                # artifact.  Re-read the authoritative checkout state before
                # any scan artifact can be published.
                scan.require_publication()
                execution_control.checkpoint()
            artifacts = _artifacts(
                scan,
                repair,
                target=self._target,
                environment=environment,
            )
            graph_reference = next(
                artifact.reference for artifact in artifacts if artifact.purpose == "evidence-graph"
            )
            outcome = _worker_outcome(scan.composition.run.audit_outcome)
            if repair is not None and repair.exit_code != 0:
                outcome = "INDETERMINATE"
            result = WorkerExecutionResult(
                outcome=outcome,
                artifacts=artifacts,
                findings=_findings(scan, graph_reference),
                scan=scan,
                repair=repair,
            )
            scan_transferred = True
            return result
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
        finally:
            try:
                if scan is not None and not scan_transferred:
                    with suppress(Exception):
                        scan.cancel()
                if provider_runtime is not None:
                    with suppress(Exception):
                        provider_runtime.close()
            finally:
                execution_control.finish_execution()


def _require_exact_checkout(
    target: Path,
    executable: Path,
    expected_head: str,
    *,
    control: ExecutionControl,
) -> None:
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
        top = _git_output(
            [*command, "rev-parse", "--show-toplevel"], environment, control=control
        )
        head = _git_output(
            [*command, "rev-parse", "--verify", "HEAD"], environment, control=control
        )
        details = target.stat(follow_symlinks=False)
    except (OSError, subprocess.SubprocessError):
        raise ProductExecutionError("worker checkout verification failed") from None
    if (
        not stat.S_ISDIR(details.st_mode)
        or Path(top).resolve() != target.resolve()
        or head != expected_head
    ):
        raise ProductIdentityMismatch("worker checkout does not match the lease")


def _git_output(
    command: list[str],
    environment: Mapping[str, str],
    *,
    control: ExecutionControl,
) -> str:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(environment),
        creationflags=_subprocess_creation_flags(),
        start_new_session=os.name == "posix",
    )
    deadline = monotonic() + 10.0
    try:
        while True:
            if control.cancelled():
                _stop_child(process)
                control.checkpoint()
            remaining = deadline - monotonic()
            if remaining <= 0:
                _stop_child(process)
                raise subprocess.TimeoutExpired(command, 10.0)
            try:
                output, _ = process.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            _stop_child(process)
    if process.returncode or output is None or len(output) > 65536:
        raise ProductExecutionError("worker checkout verification failed")
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ProductExecutionError("worker checkout verification failed") from None


def _stop_child(process: subprocess.Popen[bytes]) -> None:
    # On POSIX the group can outlive its leader when a helper process inherited
    # one of the pipes.  Kill the group even after Popen has reaped that leader.
    if os.name == "posix" or process.poll() is None:
        _kill_process_tree(process)
    try:
        process.communicate(timeout=_CHILD_EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        if os.name == "posix" or process.poll() is None:
            _kill_process_tree(process)
        try:
            process.communicate(timeout=_CHILD_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise ProductExecutionError("worker child process did not stop") from None


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Kill the isolated Git process group so cancellation cannot orphan children."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            if process.poll() is None:
                with suppress(OSError):
                    process.kill()
        return
    if process.poll() is None:
        with suppress(OSError):
            process.kill()


def _subprocess_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess).get("CREATE_NO_WINDOW", 0))


def _contribution_environment(job: WorkerJob, environment: Mapping[str, str]) -> dict[str, str]:
    restricted = job.contribution_trust in {
        WorkerContributionTrust.UNTRUSTED_FORK,
        WorkerContributionTrust.UNTRUSTED_SAME_REPOSITORY,
        WorkerContributionTrust.UNKNOWN,
    }
    if not restricted:
        return dict(environment)
    return {
        key: value
        for key, value in environment.items()
        if isinstance(key, str) and key.upper() in _SAFE_UNTRUSTED_CONFIGURATION_ENVIRONMENT
    }


def _remote_provider_requested(
    expected: object, host: LocalProductHost, environment: Mapping[str, str]
) -> bool:
    """Select the remote composition only from an explicit or identity-bound request."""

    if any(
        environment.get(name)
        for name in (
            "SECURECODE_REMOTE_PROFILE_FILE",
            "SECURECODE_REMOTE_POLICY_FILE",
            "SECURECODE_REMOTE_SPEND_DB",
        )
    ) or environment.get("SECURECODE_REMOTE_PROVIDER") == "1":
        return True
    try:
        return (
            expected.provider_profile.content_sha256
            != host.profile.canonical_content_hash()
        )
    except (AttributeError, TypeError, ValueError):
        raise ProductExecutionError("worker provider identity is invalid") from None


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


def _requested_operation(job: WorkerJob) -> WorkerOperation:
    """Use only the operation bound to the durable worker job."""

    return job.operation


def _artifacts(
    scan: LocalProductScanResult,
    repair: LocalProductRepairResult | None = None,
    *,
    target: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[WorkerArtifact, ...]:
    run = scan.composition.run
    tenant_id = run.execution_identity.repository_revision.tenant_id
    artifacts = [
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
        _evidence_graph_artifact(scan, tenant_id=tenant_id),
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
    ]
    if repair is not None:
        artifacts.append(
            _artifact(
                tenant_id=tenant_id,
                purpose="repair-report",
                prefix="worker-repair",
                content=repair.summary,
            )
        )
        if target is not None and environment is not None:
            artifacts.extend(
                _repair_patch_artifacts(
                    scan,
                    repair,
                    target=target,
                    environment=environment,
                )
            )
    return tuple(artifacts)


def _repair_patch_artifacts(
    scan: LocalProductScanResult,
    repair: LocalProductRepairResult,
    *,
    target: Path,
    environment: Mapping[str, str],
) -> tuple[WorkerArtifact, ...]:
    """Package validated local patches for the dedicated connected transport."""

    try:
        summary = json.loads(repair.summary.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ProductExecutionError("repair patch summary is invalid") from None
    if not isinstance(summary, Mapping):
        raise ProductExecutionError("repair patch summary is invalid")
    completed = summary.get("completed_repairs")
    if not isinstance(completed, list):
        raise ProductExecutionError("repair patch summary is invalid")
    identity = scan.composition.run.execution_identity
    revision = identity.repository_revision
    store = PatchArtifactStore(
        root=default_patch_artifact_root(environment),
        checkout=target.absolute(),
    )
    status_store = LocalPatchStatusStore()
    artifacts: list[WorkerArtifact] = []
    for item in completed:
        if not isinstance(item, Mapping):
            raise ProductExecutionError("repair patch summary is invalid")
        if item.get("patch_status") != "VALIDATED":
            continue
        finding_id = item.get("finding_id")
        selector = item.get("artifact_selector")
        attempts = item.get("attempts")
        if (
            not isinstance(finding_id, str)
            or not isinstance(selector, str)
            or not isinstance(attempts, list)
        ):
            raise ProductExecutionError("repair patch summary is invalid")
        final_attempt = attempts[-1] if attempts else None
        validation_result_sha256 = (
            final_attempt.get("validation_result_sha256")
            if isinstance(final_attempt, Mapping)
            else None
        )
        if (
            not isinstance(validation_result_sha256, str)
            or len(validation_result_sha256) != 64
            or any(character not in "0123456789abcdef" for character in validation_result_sha256)
        ):
            raise ProductExecutionError("repair patch summary is invalid")
        try:
            stored = store.load(selector)
            status = status_store.load(stored)
            manifest_path = stored.patch_path.with_suffix(".json")
            manifest_bytes = manifest_path.read_bytes()
        except (OSError, PatchArtifactError, ValueError):
            raise ProductExecutionError("repair patch artifact is unavailable") from None
        if (
            stored.finding.finding_id != finding_id
            or stored.finding.repository_revision != revision
            or status.patch.patch_status.value != "VALIDATED"
            or status.validation is None
            or status.validation.result_sha256 != validation_result_sha256
            or hashlib.sha256(manifest_bytes).hexdigest() != stored.manifest_sha256
        ):
            raise ProductIdentityMismatch("repair patch binding does not match the run")
        binding = WorkerRepairPatchBinding(
            tenant_id=revision.tenant_id,
            repository_id=revision.repository_id,
            run_id=scan.composition.run.run_id,
            finding_id=finding_id,
            head_sha=revision.head_sha,
            execution_identity_hash=identity.execution_identity_hash,
            patch_sha256=selector.removeprefix("sha256:"),
            patch_size_bytes=len(stored.patch_bytes),
            manifest_sha256=stored.manifest_sha256,
            validation_result_sha256=validation_result_sha256,
            patch_status_sha256=status.state_sha256,
        )
        bundle = _canonical_repair_patch_bundle(
            binding=binding,
            patch_bytes=stored.patch_bytes,
            manifest_bytes=manifest_bytes,
        )
        artifacts.append(
            _artifact(
                tenant_id=revision.tenant_id,
                purpose="repair-patch",
                prefix=f"worker-repair-patch-{finding_id}",
                content=bundle,
                data_class=DataClass.CONFIDENTIAL_SOURCE,
                binding=binding,
            )
        )
    return tuple(artifacts)


def _canonical_repair_patch_bundle(
    *,
    binding: WorkerRepairPatchBinding,
    patch_bytes: bytes,
    manifest_bytes: bytes,
) -> bytes:
    if (
        hashlib.sha256(patch_bytes).hexdigest() != binding.patch_sha256
        or len(patch_bytes) != binding.patch_size_bytes
        or hashlib.sha256(manifest_bytes).hexdigest() != binding.manifest_sha256
    ):
        raise ProductIdentityMismatch("repair patch content does not match its binding")
    return json.dumps(
        {
            "binding": binding.document(),
            "manifest_base64": base64.b64encode(manifest_bytes).decode("ascii"),
            "patch_base64": base64.b64encode(patch_bytes).decode("ascii"),
            "schema_version": "securecode.repair-patch.v1",
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _evidence_graph_artifact(
    scan: LocalProductScanResult, *, tenant_id: str
) -> WorkerArtifact:
    digest = hashlib.sha256(scan.graph_artifact).hexdigest()
    report_findings = scan.composition.report.findings
    if report_findings:
        reference = report_findings[0].finding.evidence_graph_ref
        if any(item.finding.evidence_graph_ref != reference for item in report_findings):
            raise ProductIdentityMismatch("product findings do not share one evidence graph")
        if (
            reference.tenant_id != tenant_id
            or reference.content_sha256 != digest
            or reference.size_bytes != len(scan.graph_artifact)
            or reference.data_class is not DataClass.CONFIDENTIAL_SECURITY
        ):
            raise ProductIdentityMismatch("product evidence graph reference is invalid")
        return WorkerArtifact(
            reference=reference,
            purpose="evidence-graph",
            content=scan.graph_artifact,
        )
    return _artifact(
        tenant_id=tenant_id,
        purpose="evidence-graph",
        prefix="worker-graph",
        content=scan.graph_artifact,
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
            or reference != graph_reference
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
    finding_ids = tuple(value.finding_id for value in values)
    if finding_ids != tuple(sorted(finding_ids)) or len(finding_ids) != len(set(finding_ids)):
        raise ProductExecutionError("product findings are not canonical")
    return tuple(values)


def _artifact(
    *,
    tenant_id: str,
    purpose: str,
    prefix: str,
    content: bytes,
    data_class: DataClass = DataClass.CONFIDENTIAL_SECURITY,
    binding: WorkerRepairPatchBinding | None = None,
) -> WorkerArtifact:
    digest = hashlib.sha256(content).hexdigest()
    reference = ArtifactRef(
        schema_version="0.2.0",
        tenant_id=tenant_id,
        content_id=f"{prefix}-{digest[:32]}",
        content_sha256=digest,
        size_bytes=len(content),
        data_class=data_class,
    )
    return WorkerArtifact(reference=reference, purpose=purpose, content=content, binding=binding)


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
