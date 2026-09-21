"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    Evidence,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelUsage,
)
from securecode_ai.core.auditor import AuditorResponse
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.investigation import AuditorInvocation

from .model import (
    HmacContentIdentifier,
    PreparedModelContext,
)
from .product_model import (
    AUDITOR_WIRE_SCHEMA_JSON,
    AuditorPayloadValidator,
)
from .product_runtime_contracts import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    EvidenceResolver,
    RepositoryContextBudgetExhausted,
    _snapshot_evidence_catalogue,
)
from .product_runtime_execution import (
    AuthorizedLocalModelExecutor,
    _context,
    _result_with_calls,
)


@dataclass(frozen=True, slots=True)
class ProductAuditorInvocationObservation:
    """Source-free capture before collection, not a final receipt or admission authority."""

    request: ModelRequest
    package: EvidencePackage
    usage_before_collection: ModelUsage
    model_call_status_before_collection: ModelCallStatus
    schema_valid_result_before_collection: bool

    def __post_init__(self) -> None:
        if (
            type(self.request) is not ModelRequest
            or type(self.package) is not EvidencePackage
            or type(self.usage_before_collection) is not ModelUsage
            or type(self.model_call_status_before_collection) is not ModelCallStatus
            or type(self.schema_valid_result_before_collection) is not bool
        ):
            raise ValueError("Auditor observation metadata is invalid")
        object.__setattr__(
            self, "request", ModelRequest.model_validate_json(self.request.model_dump_json())
        )
        object.__setattr__(self, "package", copy.deepcopy(self.package))
        object.__setattr__(
            self,
            "usage_before_collection",
            ModelUsage.model_validate_json(self.usage_before_collection.model_dump_json()),
        )


class ProductAuditorInvoker:
    """Core Auditor port using the authorized executor and package-bound strict wire leaf."""

    __slots__ = ("_catalogue", "_executor", "_key", "_observer", "_request_factory", "_resolver")

    def __init__(
        self,
        *,
        executor: AuthorizedLocalModelExecutor,
        resolver: EvidenceResolver,
        evidence_catalogue: tuple[Evidence, ...],
        content_key: bytes,
        request_factory: Callable[[EvidencePackage, int, object], ModelRequest],
        observer: Callable[[ProductAuditorInvocationObservation], None] | None = None,
    ) -> None:
        if (
            type(executor) is not AuthorizedLocalModelExecutor
            or not callable(getattr(resolver, "resolve", None))
            or type(content_key) is not bytes
            or len(content_key) < 32
            or not callable(request_factory)
            or (observer is not None and not callable(observer))
        ):
            raise ValueError("auditor invoker is invalid")
        self._executor = executor
        self._resolver = resolver
        self._catalogue = _snapshot_evidence_catalogue(evidence_catalogue)
        self._key = bytes(content_key)
        self._request_factory = request_factory
        self._observer = observer

    def invoke(self, package: EvidencePackage, *, attempt: int) -> AuditorInvocation:
        if type(package) is not EvidencePackage or type(attempt) is not int or attempt < 1:
            raise ValueError("auditor invocation is invalid")
        started = self._executor.clock()
        package = replace(package, selected=tuple(replace(item) for item in package.selected))
        before_calls = self._resolver.calls_used
        if type(before_calls) is not int or before_calls < 0:
            raise ValueError("auditor observed calls are invalid")
        validator = AuditorPayloadValidator(
            package=package, content_identifier=HmacContentIdentifier(self._key)
        )
        request = self._request_factory(copy.deepcopy(package), attempt, validator.validator)
        if type(request) is not ModelRequest:
            raise ValueError("auditor request is invalid")
        request = ModelRequest.model_validate_json(request.model_dump_json())
        if (
            request.role is not ModelRole.AUDITOR
            or request.mode is not ModelPurpose.CANDIDATE_INVESTIGATION
            or request.attempt != attempt
            or request.tenant_id != package.tenant_id
            or request.head_sha != package.head_sha
            or request.evidence != package.model_evidence
            or request.output_schema != validator.validator
            or request.prompt != PRODUCT_AUDITOR_PROMPT_PIN
        ):
            raise ValueError("auditor request bindings are invalid")
        ceiling_hit = False

        def build() -> PreparedModelContext:
            nonlocal ceiling_hit
            try:
                resolved = self._resolver.resolve(
                    package, max_calls=request.budget.max_repository_calls
                )
            except RepositoryContextBudgetExhausted:
                ceiling_hit = True
                raise
            if self._resolver.calls_used - before_calls > request.budget.max_repository_calls:
                ceiling_hit = True
                raise RepositoryContextBudgetExhausted("auditor context tool ceiling exhausted")
            selected = {item.evidence_id: item for item in package.selected}
            if (
                type(resolved) is not tuple
                or len(resolved) != len(selected)
                or len({item.evidence_id for item in resolved}) != len(resolved)
                or {item.evidence_id for item in resolved} != set(selected)
            ):
                raise ValueError("auditor evidence resolution is incomplete")
            entries: list[tuple[str, ArtifactRef, bytes]] = []
            for item in resolved:
                expected = selected[item.evidence_id]
                authoritative = self._catalogue.get(item.evidence_id)
                if (
                    authoritative is None
                    or item.evidence != authoritative
                    or authoritative.tenant_id != package.tenant_id
                    or authoritative.head_sha != package.head_sha
                    or authoritative.evidence_sha256 != expected.evidence_sha256
                    or authoritative.producer.producer_id != expected.producer_id
                    or authoritative.producer.producer_version != expected.producer_version
                    or authoritative.producer.producer_sha256 != expected.producer_sha256
                    or authoritative.artifact_ref != item.artifact
                    or item.artifact.content_id != expected.content_id
                    or item.artifact.data_class is not expected.data_class
                    or item.artifact.size_bytes != item.content.__len__()
                    or item.artifact.size_bytes != expected.context_bytes
                    or hashlib.sha256(item.content).hexdigest() != item.artifact.content_sha256
                ):
                    raise ValueError("auditor evidence identity mismatch")
                entries.append((item.evidence_id, item.artifact, item.content))
            return _context(
                request=request,
                entries=tuple(entries),
                key=self._key,
                role="auditor",
                schema=AUDITOR_WIRE_SCHEMA_JSON,
            )

        execution = self._executor.execute(
            request=request, validator=validator, context_builder=build, started_at=started
        )
        after_calls = self._resolver.calls_used
        if type(after_calls) is not int or after_calls < before_calls:
            if execution.payload is not None:
                execution.payload.close()
            raise ValueError("auditor observed calls are invalid")
        calls = after_calls - before_calls
        result = _result_with_calls(
            execution.result,
            calls,
            request=request,
            preflight=execution.preflight,
            elapsed_ms=self._executor.elapsed_since(started),
            budget_exhausted=ceiling_hit,
        )
        usage = result.usage
        try:
            if (
                result.model_call_status is not ModelCallStatus.SUCCEEDED
                or execution.payload is None
            ):
                response = AuditorResponse(result.model_call_status, False, None)
            else:
                payload = execution.payload.reveal_for(request.request_id)
                verdict = validator.parse(payload, request=request)
                result = _result_with_calls(
                    result, calls, request=request, elapsed_ms=self._executor.elapsed_since(started)
                )
                response = (
                    AuditorResponse(ModelCallStatus.SUCCEEDED, True, verdict)
                    if result.status is ModelCallStatus.SUCCEEDED
                    else AuditorResponse(result.status, False, None)
                )
        except Exception:
            response = AuditorResponse(ModelCallStatus.INVALID_SCHEMA, False, None)
        finally:
            if execution.payload is not None:
                execution.payload.close()
        elapsed_ms = result.usage.elapsed_ms
        # Emit only after the source-bearing payload is closed. The sink is a
        # trusted host dependency and cannot grant provider/profile authority.
        if self._observer is not None:
            observation = ProductAuditorInvocationObservation(
                request=request,
                package=package,
                usage_before_collection=ModelUsage(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    repository_calls=calls,
                    elapsed_ms=result.usage.elapsed_ms,
                ),
                model_call_status_before_collection=response.model_call_status,
                schema_valid_result_before_collection=response.schema_valid_result,
            )
            try:
                self._observer(observation)
            except Exception:
                # Preserve measured work while failing required trace collection.
                response = AuditorResponse(ModelCallStatus.GUARDRAIL_BLOCKED, False, None)
            elapsed_ms = self._executor.elapsed_since(started)
            if elapsed_ms >= request.budget.timeout_ms:
                response = AuditorResponse(ModelCallStatus.BUDGET_EXHAUSTED, False, None)
        return AuditorInvocation(
            response=response,
            tokens_used=usage.input_tokens + usage.output_tokens,
            tool_calls=calls,
            elapsed_ms=elapsed_ms,
        )
