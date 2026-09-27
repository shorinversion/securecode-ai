"""Authorized local Architect invocation for installed repair suggestions."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securecode_ai.contracts import (
    ComponentPin,
    DataClass,
    EgressContentRef,
    Evidence,
    EvidenceInputRef,
    ExecutionBoundary,
    ModelCallBudget,
    ModelCallResult,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelSchemaStatus,
    ModelUsage,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer, PayloadValidation
from securecode_ai.core.architect import ArchitectPatchResult, TouchedSymbol, emit_patch_candidate
from securecode_ai.core.repair_loop import AttemptUsage, RetryFeedback

from .endpoint import EndpointAuthorizationIssuer
from .git_snapshot import GitRevisionSnapshot, OfflineGitObjectReader, materialize_git_snapshot
from .local_product_host import LocalProductHost, verify_local_git_executable
from .local_product_runner_config import LocalProductScanResult, _git, _hash, _pin
from .local_repair_contracts import LocalRepairBinding
from .local_repair_model_payload import (
    canonical_architect_payload,
    validated_retained_architect_document,
)
from .local_repair_model_schema import (
    _ARCHITECT_INSTRUCTIONS,
    _ARCHITECT_SCHEMA,
    ARCHITECT_OUTPUT_PIN,
    ARCHITECT_PROMPT_PIN,
)
from .model import HmacContentIdentifier, PreparedModelContext
from .model_harness import AuthorizedProviderHarness
from .openai_compatible_local import OpenAICompatibleLocalHttpConnector
from .product_runtime import AuthorizedLocalModelExecutor
from .product_provider_runtime import ProductProviderRuntime
from .remote_provider_budget import RemoteProviderCostReceipt

_MAX_CONTEXT_BYTES: Final = 65_536
_MAX_SOURCE_BYTES: Final = 40_000


class LocalRepairModelError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("local Architect proposal failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class LocalArchitectProposal:
    result: ArchitectPatchResult
    patch_bytes: bytes
    author: ProducerRef
    model_result_sha256: str
    usage: AttemptUsage
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    model_receipt_id: str


class _LiteralLoopbackResolver:
    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        del port
        address = ipaddress.ip_address(authority)
        if not address.is_loopback:
            raise ValueError("local endpoint unavailable")
        return (str(address),)


class _ArchitectPayloadValidator:
    __slots__ = ("_allowed_paths", "_binding", "_content_identifier", "_snapshot")

    def __init__(
        self,
        *,
        binding: LocalRepairBinding,
        snapshot: GitRevisionSnapshot,
        allowed_paths: tuple[str, ...],
        content_identifier: HmacContentIdentifier,
    ) -> None:
        self._binding = binding
        self._snapshot = snapshot
        self._allowed_paths = allowed_paths
        self._content_identifier = content_identifier

    @property
    def validator(self) -> ComponentPin:
        return ARCHITECT_OUTPUT_PIN

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
        reason: str | None = None
        try:
            encoded = self.canonical_payload(payload, request=request)
        except Exception:
            reason = "SCHEMA_INVALID"
            encoded = b""
        if request.output_schema != self.validator:
            reason = "VALIDATOR_PIN_MISMATCH"
        if reason is not None:
            return PayloadValidation(False, reason, None, None, self.validator)
        return PayloadValidation(
            True,
            None,
            self._content_identifier.identify(tenant_id=request.tenant_id, payload=encoded),
            DataClass.CONFIDENTIAL_SOURCE,
            self.validator,
        )

    def canonical_payload(self, payload: object, *, request: ModelRequest) -> bytes:
        if request.output_schema != self.validator:
            raise ValueError
        return canonical_architect_payload(
            payload,
            binding=self._binding,
            snapshot=self._snapshot,
            allowed_paths=self._allowed_paths,
        )


def generate_local_patch(
    *,
    target: str,
    host: LocalProductHost,
    scan_result: LocalProductScanResult,
    binding: LocalRepairBinding,
    evidence: tuple[Evidence, ...],
    attempt: int = 1,
    retry_feedback: RetryFeedback | None = None,
    cancelled: Callable[[], bool] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    provider_runtime: ProductProviderRuntime | None = None,
) -> LocalArchitectProposal:
    if (
        type(attempt) is not int
        or attempt < 1
        or attempt > 3
        or (attempt == 1 and retry_feedback is not None)
        or (attempt > 1 and type(retry_feedback) is not RetryFeedback)
    ):
        raise LocalRepairModelError("REPAIR_ATTEMPT_INVALID")
    identity = scan_result.composition.run.execution_identity
    _validate_host_identity(host, identity, provider_runtime=provider_runtime)
    _validate_binding_revision(binding, identity.repository_revision)
    snapshot = _snapshot(target, host, identity.repository_revision.head_sha)
    allowed_paths = tuple(sorted({item.path for item in binding.finding.locations}))
    if not allowed_paths:
        raise LocalRepairModelError("REPAIR_SOURCE_SCOPE_EMPTY")
    source_files = {item.path: item for item in snapshot.files}
    if any(path not in source_files for path in allowed_paths):
        raise LocalRepairModelError("REPAIR_SOURCE_SCOPE_MISMATCH")
    for location in binding.finding.locations:
        file = source_files.get(location.path)
        if file is None or file.content_sha256 != location.content_sha256:
            raise LocalRepairModelError("REPAIR_SOURCE_IDENTITY_MISMATCH")
    operation = provider_runtime.repair() if provider_runtime is not None else None
    profile = host.profile if operation is None else operation.profile
    policy = host.policy if operation is None else operation.policy
    registry = host.registry if operation is None else operation.registry
    max_output = min(
        4096, profile.capabilities.max_output_tokens, profile.budgets.max_total_tokens // 2
    )
    max_input = min(
        8192,
        profile.capabilities.max_context_tokens,
        profile.budgets.max_total_tokens - max_output,
    )
    if max_input < max_output:
        raise LocalRepairModelError("REPAIR_MODEL_BUDGET_INVALID")
    feedback_hash = retry_feedback.feedback_sha256 if retry_feedback is not None else "initial"
    token = hashlib.sha256(
        (
            binding.finding.finding_id
            + "\x00"
            + identity.execution_identity_hash
            + "\x00"
            + str(attempt)
            + "\x00"
            + feedback_hash
        ).encode("ascii")
    ).hexdigest()
    evidence_inputs = _evidence_inputs(evidence, binding)
    request = ModelRequest(
        schema_version="0.2.0",
        request_id="architect-" + token,
        run_id=scan_result.composition.run.run_id,
        tenant_id=identity.repository_revision.tenant_id,
        idempotency_key="architect-" + token,
        attempt=attempt,
        execution_identity=identity,
        head_sha=identity.repository_revision.head_sha,
        role=ModelRole.ARCHITECT,
        mode=ModelPurpose.PATCH_GENERATION,
        provider_profile=identity.provider_profile,
        api_dialect=profile.api_dialect,
        model_id=profile.model_id,
        prompt=ARCHITECT_PROMPT_PIN,
        output_schema=ARCHITECT_OUTPUT_PIN,
        tool_policy=_pin("no-repository-tools", "1.0.0", _hash({"tools": []})),
        repository_scope=_pin(
            "confirmed-finding-scope",
            "1.0.0",
            _hash(
                {
                    "head": identity.repository_revision.head_sha,
                    "paths": allowed_paths,
                }
            ),
        ),
        repository_view_policy=_pin(
            "bounded-repair-view",
            "1.0.0",
            _hash({"class": "DC3", "paths": allowed_paths, "immutable": True}),
        ),
        evidence=evidence_inputs,
        budget=ModelCallBudget(
            schema_version="0.2.0",
            max_input_tokens=max_input,
            max_output_tokens=max_output,
            max_repository_calls=1,
            max_context_bytes=_MAX_CONTEXT_BYTES,
            timeout_ms=profile.budgets.timeout_seconds * 1000,
        ),
    )
    issuer = ModelAuthorizationIssuer(
        provider_registry=registry,
        policy_registry=EgressPolicyRegistry((policy,)),
    )

    def preflight(selected: ModelRequest) -> ModelPreflightRequest:
        return ModelPreflightRequest(
            schema_version="0.2.0",
            model_request=selected,
            required_execution_boundary=profile.execution_boundary,
            required_data_class=DataClass.CONFIDENTIAL_SOURCE,
            required_purpose=ModelPurpose.PATCH_GENERATION,
            planned_transforms=("bounded_repository_view",),
            required_max_bytes=selected.budget.max_context_bytes,
        )

    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=issuer,
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=_LiteralLoopbackResolver() if operation is None else operation.resolver,
        connector=(
            OpenAICompatibleLocalHttpConnector(profile=profile, cancelled=cancelled)
            if operation is None
            else operation.connector
        ),
        preflight=preflight,
        credential_supplier=None if operation is None else operation.credential_supplier,
        usage_observer=usage_observer,
        cost_observer=cost_observer,
    )
    content_key = os.urandom(32)
    identifier = HmacContentIdentifier(content_key)
    validator = _ArchitectPayloadValidator(
        binding=binding,
        snapshot=snapshot,
        allowed_paths=allowed_paths,
        content_identifier=identifier,
    )
    execution = executor.execute(
        request=request,
        validator=validator,
        context_builder=lambda: _context(
            request=request,
            binding=binding,
            snapshot=snapshot,
            allowed_paths=allowed_paths,
            content_identifier=identifier,
            retry_feedback=retry_feedback,
        ),
    )
    if (
        execution.result is None
        or execution.result.status is not ModelCallStatus.SUCCEEDED
        or execution.payload is None
    ):
        raise LocalRepairModelError("ARCHITECT_MODEL_NON_SUCCESS")
    model_result = execution.result
    if (
        type(model_result) is not ModelCallResult
        or model_result.request_id != request.request_id
        or model_result.run_id != request.run_id
        or model_result.tenant_id != request.tenant_id
        or model_result.attempt != request.attempt
        or model_result.provider_profile != request.provider_profile
        or model_result.model_call_status is not ModelCallStatus.SUCCEEDED
        or model_result.schema_result.status is not ModelSchemaStatus.VALID
    ):
        raise LocalRepairModelError("ARCHITECT_MODEL_RECEIPT_INVALID")
    try:
        document = validated_retained_architect_document(
            execution.payload.reveal_for(request.request_id),
            binding=binding,
            snapshot=snapshot,
            allowed_paths=allowed_paths,
        )
    finally:
        execution.payload.close()
    symbols = tuple(TouchedSymbol(**item) for item in document["touched_symbols"])
    author = ProducerRef(
        schema_version="0.2.0",
        producer_id=(
            "installed-local-architect"
            if operation is None
            else "installed-remote-architect"
        ),
        producer_version="1.0.0",
        producer_sha256=ARCHITECT_PROMPT_PIN.content_sha256,
    )
    result = emit_patch_candidate(
        binding.finding,
        binding.root_cause,
        binding.invariant,
        binding.regression,
        unified_diff=document["unified_diff"],
        rationale=document["rationale"],
        touched_symbols=symbols,
        author=author,
    )
    patch_bytes = document["unified_diff"].encode("utf-8")
    return LocalArchitectProposal(
        result,
        patch_bytes,
        author,
        hashlib.sha256(execution.result.model_dump_json().encode("utf-8")).hexdigest(),
        AttemptUsage(
            tokens_used=model_result.usage.input_tokens + model_result.usage.output_tokens,
            tool_calls=model_result.usage.repository_calls,
            elapsed_ms=model_result.usage.elapsed_ms,
        ),
        model_result.model_call_status,
        model_result.schema_result.status is ModelSchemaStatus.VALID,
        model_result.request_id,
    )


def _validate_host_identity(
    host: LocalProductHost,
    identity: RunExecutionIdentity,
    *,
    provider_runtime: ProductProviderRuntime | None = None,
) -> None:
    profile = host.profile if provider_runtime is None else provider_runtime.profile
    policy = host.policy if provider_runtime is None else provider_runtime.policy
    if (
        profile.canonical_content_hash() != identity.provider_profile.content_sha256
        or policy.canonical_content_hash() != identity.policy.content_sha256
        or policy.tenant_scope != identity.repository_revision.tenant_id
    ):
        raise LocalRepairModelError("REPAIR_HOST_IDENTITY_MISMATCH")


def _validate_binding_revision(
    binding: LocalRepairBinding,
    repository_revision: RepositoryRevision,
) -> None:
    if (
        type(binding) is not LocalRepairBinding
        or type(repository_revision) is not RepositoryRevision
        or binding.finding.repository_revision != repository_revision
    ):
        raise LocalRepairModelError("REPAIR_BINDING_IDENTITY_MISMATCH")


def _snapshot(target: str, host: LocalProductHost, expected_head: str) -> GitRevisionSnapshot:
    root = Path(target).absolute()
    if not root.is_dir() or root.is_symlink() or "\x00" in target:
        raise LocalRepairModelError("REPAIR_TARGET_INVALID")
    try:
        git = verify_local_git_executable(host.artifact_manifest.get("git_executable_sha256", ""))
        checkout = Path(_git(root, git, "rev-parse", "--show-toplevel")).resolve()
        if (
            checkout != root.resolve()
            or _git(checkout, git, "rev-parse", "--verify", "HEAD") != expected_head
        ):
            raise ValueError
        objects = Path(_git(checkout, git, "rev-parse", "--git-path", "objects"))
        if not objects.is_absolute():
            objects = checkout / objects
        reader = OfflineGitObjectReader(objects_dir=objects.absolute(), git_executable=git)
        snapshot = materialize_git_snapshot(reader, expected_head)
    except Exception:
        raise LocalRepairModelError("REPAIR_GIT_SNAPSHOT_UNAVAILABLE") from None
    if snapshot.head_sha != expected_head:
        raise LocalRepairModelError("REPAIR_HEAD_MISMATCH")
    return snapshot


def _evidence_inputs(
    evidence: tuple[Evidence, ...], binding: LocalRepairBinding
) -> tuple[EvidenceInputRef, ...]:
    if (
        type(binding) is not LocalRepairBinding
        or type(evidence) is not tuple
        or any(type(item) is not Evidence for item in evidence)
    ):
        raise LocalRepairModelError("REPAIR_EVIDENCE_INVALID")
    expected_ids = tuple(binding.finding.evidence_ids)
    observed_ids = tuple(item.evidence_id for item in evidence)
    if (
        len(set(expected_ids)) != len(expected_ids)
        or len(set(observed_ids)) != len(observed_ids)
        or set(observed_ids) != set(expected_ids)
    ):
        raise LocalRepairModelError("REPAIR_EVIDENCE_INVALID")
    revision = binding.finding.repository_revision
    if any(
        item.tenant_id != revision.tenant_id or item.head_sha != revision.head_sha
        for item in evidence
    ):
        raise LocalRepairModelError("REPAIR_EVIDENCE_INVALID")
    by_id = {item.evidence_id: item for item in evidence}
    inputs = []
    for evidence_id in binding.finding.evidence_ids:
        item = by_id.get(evidence_id)
        if item is None or item.data_class is DataClass.RESTRICTED:
            raise LocalRepairModelError("REPAIR_EVIDENCE_INVALID")
        content_id = (
            item.artifact_ref.content_id if item.artifact_ref is not None else item.evidence_id
        )
        inputs.append(
            EvidenceInputRef(
                schema_version="0.2.0",
                evidence_id=item.evidence_id,
                content_id=content_id,
                data_class=item.data_class,
            )
        )
    if not inputs:
        raise LocalRepairModelError("REPAIR_EVIDENCE_INVALID")
    return tuple(inputs)


def _context(
    *,
    request: ModelRequest,
    binding: LocalRepairBinding,
    snapshot: GitRevisionSnapshot,
    allowed_paths: tuple[str, ...],
    content_identifier: HmacContentIdentifier,
    retry_feedback: RetryFeedback | None = None,
) -> PreparedModelContext:
    windows = _source_windows(binding, snapshot, allowed_paths)
    content_by_id: dict[str, EgressContentRef] = {}
    for window in windows:
        window_bytes = str(window["content"]).encode("utf-8")
        content_id = content_identifier.identify(
            tenant_id=request.tenant_id,
            payload=window_bytes,
        )
        content_by_id.setdefault(
            content_id,
            EgressContentRef(
                schema_version="0.2.0",
                content_id=content_id,
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        )
    material = {
        "trusted_controls": {
            "instruction_authority": "HOST_CONTROL",
            "instructions": _ARCHITECT_INSTRUCTIONS,
            "output_schema": _ARCHITECT_SCHEMA,
            "allowed_paths": list(allowed_paths),
            "identity": {
                "finding_id": binding.finding.finding_id,
                "root_cause_id": binding.root_cause.record_id,
                "invariant_id": binding.invariant.invariant_id,
                "regression_descriptor_id": binding.regression.descriptor_id,
                "head_sha": request.head_sha,
                "command_operation_evidence": [
                    item.model_dump(mode="json")
                    for item in binding.invariant.command_operation_evidence
                ],
            },
        },
        "untrusted_repository_source": windows,
    }
    if retry_feedback is not None:
        material["trusted_controls"]["repair_retry_feedback"] = {
            "instruction": "Address each listed failed validation gate while preserving the original finding and allowed path scope.",
            "attempt": request.attempt,
            "failed_gates": [
                {"ordinal": ordinal, "gate_id": gate_id, "reason_code": reason_code}
                for ordinal, gate_id, reason_code in retry_feedback.failed_gates
            ],
            "retryable": retry_feedback.retryable,
            "feedback_sha256": retry_feedback.feedback_sha256,
        }
    payload = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if len(payload) > request.budget.max_context_bytes:
        raise LocalRepairModelError("REPAIR_CONTEXT_TOO_LARGE")
    return PreparedModelContext(
        payload=payload,
        content=tuple(content_by_id[key] for key in sorted(content_by_id)),
        applied_transforms=("bounded_repository_view",),
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        content_identifier=content_identifier,
    )


def _source_windows(
    binding: LocalRepairBinding,
    snapshot: GitRevisionSnapshot,
    allowed_paths: tuple[str, ...],
) -> list[dict[str, object]]:
    files = {item.path: item for item in snapshot.files}
    if not allowed_paths:
        raise LocalRepairModelError("REPAIR_SOURCE_SCOPE_EMPTY")
    budget_each = _MAX_SOURCE_BYTES // len(allowed_paths)
    result = []
    for path in allowed_paths:
        file = files.get(path)
        related = [item for item in binding.finding.locations if item.path == path]
        if file is None or not related:
            raise LocalRepairModelError("REPAIR_SOURCE_SCOPE_MISMATCH")
        try:
            lines = file.content.decode("utf-8", errors="strict").splitlines(keepends=True)
        except UnicodeDecodeError:
            raise LocalRepairModelError("REPAIR_SOURCE_ENCODING_INVALID") from None
        evidence_first = min(item.start.line for item in related)
        evidence_last = max(item.end.line for item in related)
        if evidence_first < 1 or evidence_last < evidence_first or evidence_last > len(lines):
            raise LocalRepairModelError("REPAIR_SOURCE_IDENTITY_MISMATCH")
        first = max(1, evidence_first - 40)
        last = min(len(lines), evidence_last + 40)
        selected = "".join(lines[first - 1 : last]).encode("utf-8")
        while len(selected) > budget_each and (first < evidence_first or last > evidence_last):
            if last - evidence_last > evidence_first - first:
                last -= 1
            else:
                first += 1
            selected = "".join(lines[first - 1 : last]).encode("utf-8")
        if (
            not selected
            or len(selected) > budget_each
            or first > evidence_first
            or last < evidence_last
        ):
            raise LocalRepairModelError("REPAIR_SOURCE_WINDOW_TOO_LARGE")
        result.append(
            {
                "instruction_authority": "NONE",
                "path": path,
                "content_sha256": file.content_sha256,
                "start_line": first,
                "end_line": last,
                "content": selected.decode("utf-8"),
            }
        )
    return result


__all__ = [
    "ARCHITECT_OUTPUT_PIN",
    "ARCHITECT_PROMPT_PIN",
    "LocalArchitectProposal",
    "LocalRepairModelError",
    "generate_local_patch",
]
