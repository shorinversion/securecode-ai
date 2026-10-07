"""Read-only Skeptic port through the authorized local provider harness."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable

from securecode_ai.contracts import (
    ArtifactRef,
    ComponentPin,
    Evidence,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
)
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.skeptic import AuditorSnapshot

from .model import HmacContentIdentifier, PreparedModelContext
from .product_review import SkepticInvocation
from .product_runtime import (
    AuthorizedLocalModelExecutor,
    EvidenceResolver,
    RepositoryContextBudgetExhausted,
    ResolvedModelEvidence,
    _result_with_calls,
    _snapshot_evidence_catalogue,
)
from .product_runtime_discovery import regeneration_request
from .product_skeptic_context import _package_matches_snapshot, _skeptic_context
from .product_skeptic_contracts import (
    _ID,
    PRODUCT_SKEPTIC_PROMPT_PIN,
    _copy_package,
    _copy_snapshot,
)
from .product_skeptic_validator import SkepticPayloadValidator

_MAX_REGENERATIONS = 2
_REGENERATE_ON = frozenset({ModelCallStatus.INVALID_SCHEMA, ModelCallStatus.EMPTY_OUTPUT})


class ProductSkepticReviewPort:
    """Read-only Skeptic port through the authorized local provider harness."""

    __slots__ = (
        "_catalogue",
        "_claim_for",
        "_executor",
        "_key",
        "_package_for",
        "_request_factory",
        "_resolver",
        "_skeptic_identity",
        "_tenant_id",
    )

    def __init__(
        self,
        *,
        executor: AuthorizedLocalModelExecutor,
        resolver: EvidenceResolver,
        evidence_catalogue: tuple[Evidence, ...],
        content_key: bytes,
        skeptic_identity: str,
        tenant_id: str,
        package_for: Callable[[AuditorSnapshot], EvidencePackage],
        request_factory: Callable[
            [AuditorSnapshot, EvidencePackage, int, ComponentPin], ModelRequest
        ],
        claim_for: Callable[[AuditorSnapshot], tuple[str, ...]] | None = None,
    ) -> None:
        if (
            type(executor) is not AuthorizedLocalModelExecutor
            or not callable(getattr(resolver, "resolve", None))
            or type(content_key) is not bytes
            or len(content_key) < 32
            or type(skeptic_identity) is not str
            or _ID.fullmatch(skeptic_identity) is None
            or type(tenant_id) is not str
            or _ID.fullmatch(tenant_id) is None
            or not callable(package_for)
            or not callable(request_factory)
        ):
            raise ValueError("Skeptic review port is invalid")
        catalogue = _snapshot_evidence_catalogue(evidence_catalogue)
        if any(record.tenant_id != tenant_id for record in catalogue.values()):
            raise ValueError("Skeptic evidence catalogue tenant is invalid")
        self._executor = executor
        self._resolver = resolver
        self._catalogue = catalogue
        self._key = bytes(content_key)
        self._skeptic_identity = skeptic_identity
        self._tenant_id = tenant_id
        self._package_for = package_for
        self._request_factory = request_factory
        self._claim_for = claim_for

    def review(self, snapshot: AuditorSnapshot) -> SkepticInvocation:
        try:
            started = self._executor.clock()
            snapshot = _copy_snapshot(snapshot)
            if snapshot.auditor_identity == self._skeptic_identity:
                return self._non_success(ModelCallStatus.INVALID_SCHEMA)
            package = _copy_package(self._package_for(copy.deepcopy(snapshot)))
            if not _package_matches_snapshot(package, snapshot, expected_tenant_id=self._tenant_id):
                return self._non_success(ModelCallStatus.INVALID_SCHEMA)
            validator = SkepticPayloadValidator(
                package=package,
                snapshot=snapshot,
                content_identifier=HmacContentIdentifier(self._key),
                expected_tenant_id=self._tenant_id,
            )
            request = self._request_factory(
                copy.deepcopy(snapshot), copy.deepcopy(package), 1, validator.validator
            )
            if type(request) is not ModelRequest:
                return self._non_success(ModelCallStatus.INVALID_SCHEMA)
            request = ModelRequest.model_validate_json(request.model_dump_json())
            if (
                request.role is not ModelRole.SKEPTIC
                or request.mode is not ModelPurpose.SKEPTIC_REVIEW
                or request.attempt != 1
                or request.tenant_id != package.tenant_id
                or request.head_sha != package.head_sha
                or request.evidence != package.model_evidence
                or request.output_schema != validator.validator
                or request.prompt != PRODUCT_SKEPTIC_PROMPT_PIN
            ):
                return self._non_success(ModelCallStatus.INVALID_SCHEMA)
        except Exception:
            return self._non_success(ModelCallStatus.INVALID_SCHEMA)

        try:
            before_calls = self._resolver.calls_used
            if type(before_calls) is not int or before_calls < 0:
                return self._non_success(ModelCallStatus.INVALID_SCHEMA)
            ceiling_hit = False
            # Evidence is read once; a repeated call reuses the verified entries.
            verified: list[tuple[tuple[str, ArtifactRef, bytes], ...]] = []

            def build_for(active: ModelRequest) -> Callable[[], PreparedModelContext]:
                def build() -> PreparedModelContext:
                    nonlocal ceiling_hit
                    if not verified:
                        try:
                            resolved = self._resolver.resolve(
                                package, max_calls=request.budget.max_repository_calls
                            )
                        except RepositoryContextBudgetExhausted:
                            ceiling_hit = True
                            raise
                        if (
                            self._resolver.calls_used - before_calls
                            > request.budget.max_repository_calls
                        ):
                            ceiling_hit = True
                            raise RepositoryContextBudgetExhausted(
                                "Skeptic context tool ceiling exhausted"
                            )
                        verified.append(self._verified_entries(package, resolved))
                    return _skeptic_context(
                        request=active,
                        snapshot=snapshot,
                        package=package,
                        entries=verified[0],
                        key=self._key,
                        rule_ids=() if self._claim_for is None else self._claim_for(snapshot),
                    )

                return build

            invocation = self._attempt(
                request, validator, build_for(request), before_calls, started, ceiling_hit
            )
            for ordinal in range(1, _MAX_REGENERATIONS + 1):
                if invocation.model_call_status not in _REGENERATE_ON:
                    break
                # A malformed or empty answer says nothing about the finding: ask again
                # under a fresh request identity, at most twice.
                retry = regeneration_request(request, content_key=self._key, ordinal=ordinal)
                invocation = self._attempt(
                    retry, validator, build_for(retry), before_calls, started, ceiling_hit
                )
            return invocation
        except Exception:
            return self._non_success(ModelCallStatus.PROVIDER_ERROR)

    def _attempt(
        self,
        request: ModelRequest,
        validator: SkepticPayloadValidator,
        build: Callable[[], PreparedModelContext],
        before_calls: int,
        started: float,
        ceiling_hit: bool,
    ) -> SkepticInvocation:
        execution = self._executor.execute(
            request=request, validator=validator, context_builder=build, started_at=started
        )
        try:
            try:
                # Host accounting faults are not a model answer: never asked again.
                after_calls = self._resolver.calls_used
                if type(after_calls) is not int or after_calls < before_calls:
                    return self._non_success(ModelCallStatus.PROVIDER_ERROR)
                result = _result_with_calls(
                    execution.result,
                    after_calls - before_calls,
                    request=request,
                    preflight=execution.preflight,
                    elapsed_ms=self._executor.elapsed_since(started),
                    budget_exhausted=ceiling_hit,
                )
            except Exception:
                return self._non_success(ModelCallStatus.PROVIDER_ERROR)
            if (
                result.model_call_status is not ModelCallStatus.SUCCEEDED
                or execution.payload is None
            ):
                return self._non_success(result.model_call_status)
            output = validator.parse(
                execution.payload.reveal_for(request.request_id), request=request
            )
            if self._executor.elapsed_since(started) >= request.budget.timeout_ms:
                return self._non_success(ModelCallStatus.BUDGET_EXHAUSTED)
            return SkepticInvocation(self._skeptic_identity, ModelCallStatus.SUCCEEDED, output)
        except Exception:
            return self._non_success(ModelCallStatus.INVALID_SCHEMA)
        finally:
            if execution.payload is not None:
                execution.payload.close()

    def _verified_entries(
        self,
        package: EvidencePackage,
        resolved: tuple[ResolvedModelEvidence, ...],
    ) -> tuple[tuple[str, ArtifactRef, bytes], ...]:
        selected = {item.evidence_id: item for item in package.selected}
        if (
            type(resolved) is not tuple
            or len(resolved) != len(selected)
            or len({item.evidence_id for item in resolved}) != len(resolved)
            or {item.evidence_id for item in resolved} != set(selected)
        ):
            raise ValueError("Skeptic evidence resolution is incomplete")
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
                or item.artifact.size_bytes != len(item.content)
                or item.artifact.size_bytes != expected.context_bytes
                or hashlib.sha256(item.content).hexdigest() != item.artifact.content_sha256
            ):
                raise ValueError("Skeptic evidence identity mismatch")
            entries.append((item.evidence_id, item.artifact, item.content))
        return tuple(entries)

    def _non_success(self, status: ModelCallStatus) -> SkepticInvocation:
        return SkepticInvocation(self._skeptic_identity, status, None)
