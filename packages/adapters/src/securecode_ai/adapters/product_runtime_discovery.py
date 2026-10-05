"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import threading
from collections.abc import Callable

from securecode_ai.contracts import (
    ArtifactRef,
    DataClass,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    SourceLocation,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryPayload,
    RepositoryToolSession,
)
from securecode_ai.core.tool_policy import (
    GuardedToolResult,
    RepositoryToolRequest,
    ToolOutcome,
)

from .model import (
    HmacContentIdentifier,
    PreparedModelContext,
)
from .product_model import (
    MODEL_NATIVE_DISCOVERY_WIRE_PIN,
    MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
    ModelNativeDiscoveryPayloadValidator,
)
from .product_runtime_contracts import (
    PRODUCT_DISCOVERY_PROMPT_PIN,
    DiscoveryEvidence,
    ProductDiscoveryInvocationObservation,
    RepositoryContextBudgetExhausted,
)
from .product_runtime_discovery_native import _ProductDiscoveryNativeCycle
from .product_runtime_execution import (
    AuthorizedLocalModelExecutor,
    _context,
    _non_success_result,
    _result_with_calls,
)
from .product_runtime_support import _draft


class ProductDiscoveryBackend(_ProductDiscoveryNativeCycle):
    """Core discovery port that reads the selected scope only after preflight."""

    __slots__ = (
        "_catalogue",
        "_data_class",
        "_executor",
        "_key",
        "_native_cycle",
        "_native_lock",
        "_native_results",
        "_observer",
        "_rule_ids",
    )

    def __init__(
        self,
        *,
        executor: AuthorizedLocalModelExecutor,
        catalogue: tuple[DiscoveryEvidence, ...],
        rule_ids: frozenset[str],
        content_key: bytes,
        native_cycle: bool = False,
        data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE,
        observer: Callable[[ProductDiscoveryInvocationObservation], None] | None = None,
    ) -> None:
        if (
            type(executor) is not AuthorizedLocalModelExecutor
            or type(catalogue) is not tuple
            or not catalogue
            or len({item.evidence_id for item in catalogue}) != len(catalogue)
            or type(rule_ids) is not frozenset
            or not rule_ids
            or type(content_key) is not bytes
            or len(content_key) < 32
            or type(native_cycle) is not bool
            or type(data_class) is not DataClass
            or data_class not in {DataClass.PUBLIC, DataClass.CONFIDENTIAL_SOURCE}
            or any(
                item.source_artifact.data_class is not data_class
                or item.read_artifact.data_class is not data_class
                for item in catalogue
            )
            or (observer is not None and not callable(observer))
        ):
            raise ValueError("discovery backend is invalid")
        self._executor = executor
        self._catalogue = tuple(
            DiscoveryEvidence(
                evidence_id=item.evidence_id,
                tenant_id=item.tenant_id,
                head_sha=item.head_sha,
                location=SourceLocation.model_validate(item.location.model_dump(mode="python")),
                source_artifact=ArtifactRef.model_validate(
                    item.source_artifact.model_dump(mode="python")
                ),
                read_artifact=ArtifactRef.model_validate(
                    item.read_artifact.model_dump(mode="python")
                ),
                request=item.request,
            )
            for item in catalogue
        )
        self._data_class = data_class
        self._rule_ids = frozenset(rule_ids)
        self._key = bytes(content_key)
        self._native_cycle = native_cycle
        self._observer = observer
        self._native_lock = threading.Lock()
        self._native_results: dict[
            str, tuple[str, int, tuple[str, ...], ModelNativeDiscoveryPayload]
        ] = {}

    def excluding_paths(self, paths: frozenset[str]) -> ProductDiscoveryBackend:
        """Return a backend whose seed omits files the host withholds from the model.

        A file with a detected secret is read only through the masking view; seeding it
        would compare masked bytes with the raw anchor and fail the whole lane. When every
        anchor is withheld the original backend is kept, so the lane stays fail-closed.
        """

        if type(paths) is not frozenset or any(type(path) is not str for path in paths):
            raise ValueError("discovery exclusion is invalid")
        kept = tuple(item for item in self._catalogue if item.location.path not in paths)
        if not kept or len(kept) == len(self._catalogue):
            return self
        clone = object.__new__(ProductDiscoveryBackend)
        for name in self.__slots__:
            object.__setattr__(clone, name, getattr(self, name))
        clone._catalogue = kept
        clone._native_lock = threading.Lock()
        clone._native_results = {}
        return clone

    def discover(
        self, *, request: ModelRequest, tools: RepositoryToolSession
    ) -> ModelNativeDiscoveryPayload:
        if type(request) is not ModelRequest or type(tools) is not RepositoryToolSession:
            raise ValueError("discovery request is invalid")
        request = ModelRequest.model_validate_json(request.model_dump_json())
        started = self._executor.clock()
        if (
            request.role is not ModelRole.DISCOVERY
            or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or request.output_schema != MODEL_NATIVE_DISCOVERY_WIRE_PIN
            or request.prompt != PRODUCT_DISCOVERY_PROMPT_PIN
            or request.evidence
            or any(
                item.tenant_id != request.tenant_id or item.head_sha != request.head_sha
                for item in self._catalogue
            )
        ):
            if self._native_cycle:
                return ModelNativeDiscoveryPayload(
                    model_result=_non_success_result(
                        request, ModelCallStatus.INVALID_SCHEMA, 0, 0, None
                    ),
                    candidates=(),
                )
            raise ValueError("discovery request bindings are invalid")
        if self._native_cycle:
            return self._discover_native(request=request, tools=tools, started=started)
        by_id = {item.evidence_id: item for item in self._catalogue}
        before_calls = tools.calls_used
        ceiling_hit = False
        validator = ModelNativeDiscoveryPayloadValidator(
            content_identifier=HmacContentIdentifier(self._key),
            rule_ids=self._rule_ids,
            evidence_ids=frozenset(by_id),
            expected_tenant_id=request.tenant_id,
            expected_head_sha=request.head_sha,
        )

        def build() -> PreparedModelContext:
            nonlocal ceiling_hit
            entries: list[tuple[str, ArtifactRef, bytes]] = []
            reads: list[tuple[RepositoryToolRequest, GuardedToolResult]] = []
            for item in self._catalogue:
                cached = next(
                    (result for selected, result in reads if selected == item.request), None
                )
                if (
                    cached is None
                    and tools.calls_used - before_calls >= request.budget.max_repository_calls
                ):
                    ceiling_hit = True
                    raise RepositoryContextBudgetExhausted(
                        "discovery context tool ceiling exhausted"
                    )
                result = cached
                if result is None:
                    result = tools.dispatch(item.request)
                    reads.append((item.request, result))
                if result.receipt.outcome is not ToolOutcome.SUCCEEDED or result.output is None:
                    raise ValueError("required discovery evidence was not read")
                output = result.output
                if (
                    output.content_sha256 != item.read_artifact.content_sha256
                    or output.byte_count != item.read_artifact.size_bytes
                    or item.read_artifact.tenant_id != request.tenant_id
                    or item.tenant_id != request.tenant_id
                    or item.head_sha != request.head_sha
                    or getattr(item.request.arguments, "head_sha", None) != request.head_sha
                ):
                    raise ValueError("discovery evidence identity mismatch")
                entries.append((item.evidence_id, item.read_artifact, output.content.encode()))
            if tools.calls_used - before_calls > request.budget.max_repository_calls:
                ceiling_hit = True
                raise RepositoryContextBudgetExhausted("discovery context tool ceiling exhausted")
            return _context(
                request=request,
                entries=tuple(entries),
                key=self._key,
                role="discovery",
                schema=MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
                rule_ids=tuple(sorted(self._rule_ids)),
                locations=tuple((item.evidence_id, item.location) for item in self._catalogue),
            )

        execution = self._executor.execute(
            request=request, validator=validator, context_builder=build, started_at=started
        )
        if (
            execution.result is None
            or execution.result.model_call_status is not ModelCallStatus.SUCCEEDED
            or execution.payload is None
        ):
            try:
                return ModelNativeDiscoveryPayload(
                    model_result=_result_with_calls(
                        execution.result,
                        tools.calls_used - before_calls,
                        request=request,
                        preflight=execution.preflight,
                        elapsed_ms=self._executor.elapsed_since(started),
                        budget_exhausted=ceiling_hit,
                    ),
                    candidates=(),
                )
            finally:
                if execution.payload is not None:
                    execution.payload.close()
        try:
            payload = execution.payload.reveal_for(request.request_id)
            wire = validator.parse(payload)
            drafts = tuple(_draft(item, by_id, request) for item in wire)
            result = _result_with_calls(
                execution.result,
                tools.calls_used - before_calls,
                request=request,
                preflight=execution.preflight,
                elapsed_ms=self._executor.elapsed_since(started),
                budget_exhausted=ceiling_hit,
            )
            if result.model_call_status is not ModelCallStatus.SUCCEEDED:
                raise ValueError("tool usage exceeds model budget")
            return ModelNativeDiscoveryPayload(model_result=result, candidates=drafts)
        except Exception:
            return ModelNativeDiscoveryPayload(
                model_result=_result_with_calls(
                    execution.result,
                    tools.calls_used - before_calls,
                    request=request,
                    failed=True,
                    preflight=execution.preflight,
                    elapsed_ms=self._executor.elapsed_since(started),
                    budget_exhausted=ceiling_hit,
                ),
                candidates=(),
            )
        finally:
            execution.payload.close()
