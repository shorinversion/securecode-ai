"""Mandatory, bounded model-native discovery over an immutable RepositoryView.

This Core component deliberately does not implement a provider transport or a
filesystem view.  It coordinates a *previously authorized* model-native call
with :class:`RepositoryToolGuard`, retaining only typed candidates and safe
hashes.  Repository text is never a control input: it is available to a
backend only through the four guarded, read-only operations and continues to
have ``instruction_authority=NONE``.

Provider/egress admission is owned by the P1.8 model boundary.  An ineligible
preflight stops here before a repository handle or discovery backend is used;
there is no deterministic-only fallback path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import (
    AuditRunOutcome,
    DiscoveryCandidate,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    PreflightEligibility,
    ProducerRef,
)
from securecode_ai.contracts import (
    ModelDiscoveryReceipt as ModelDiscoveryReceipt,
)
from securecode_ai.contracts import (
    ModelPurpose as ModelPurpose,
)
from securecode_ai.contracts import (
    ModelRole as ModelRole,
)

from .tool_policy import (
    GuardedToolResult,
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolReceipt,
    RepositoryToolScope,
    RepositoryView,
    ToolOutcome,
    ToolReason,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CANDIDATES: Final = 4_096
_MAX_USAGE: Final = 9_007_199_254_740_991


class ModelNativeDiscoveryErrorCode(StrEnum):
    """Closed, non-echoing construction failures for this coordinator."""

    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class ModelNativeDiscoveryError(ValueError):
    """A safe setup error; provider and repository data are never rendered."""

    __slots__ = ("code",)

    def __init__(self, code: ModelNativeDiscoveryErrorCode) -> None:
        if type(code) is not ModelNativeDiscoveryErrorCode:
            raise TypeError("model-native discovery error code is invalid")
        self.code = code
        super().__init__("model-native discovery setup failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class ModelNativeCandidateDraft:
    """A parsed, source-free candidate supplied by a provider adapter.

    ``source_id`` identifies the model-native hypothesis that produced this
    candidate.  It is deliberately separate from ``candidate_id`` so lineage
    cannot be silently reconstructed from a later normalized candidate.
    """

    candidate_id: str
    candidate_version: int
    source_id: str
    root_cause_fingerprint: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.candidate_id, self.source_id)
            )
            or type(self.candidate_version) is not int
            or isinstance(self.candidate_version, bool)
            or self.candidate_version < 1
            or type(self.root_cause_fingerprint) is not str
            or _SHA256.fullmatch(self.root_cause_fingerprint) is None
            or type(self.evidence_ids) is not tuple
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in self.evidence_ids
            )
            or len(self.evidence_ids) != len(set(self.evidence_ids))
        ):
            raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.INVALID_REQUEST)
        object.__setattr__(self, "evidence_ids", tuple(sorted(self.evidence_ids)))


@dataclass(frozen=True, slots=True)
class ModelNativeDiscoveryPayload:
    """Provider-normalized result plus ephemeral, parsed candidate metadata."""

    model_result: ModelCallResult
    candidates: tuple[ModelNativeCandidateDraft, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.model_result) is not ModelCallResult
            or type(self.candidates) is not tuple
            or len(self.candidates) > _MAX_CANDIDATES
            or any(type(item) is not ModelNativeCandidateDraft for item in self.candidates)
            or len({item.candidate_id for item in self.candidates}) != len(self.candidates)
            or (
                self.model_result.model_call_status is not ModelCallStatus.SUCCEEDED
                and self.candidates
            )
        ):
            raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.INVALID_REQUEST)
        object.__setattr__(
            self,
            "candidates",
            tuple(sorted(self.candidates, key=lambda item: item.candidate_id)),
        )


class ModelNativeDiscoveryBackend(Protocol):
    """Adapter port for one pre-authorized model-native discovery attempt.

    A backend may call ``tools.dispatch`` zero or more times, but cannot obtain
    the repository view, a shell, a network capability or mutable policy.  The
    provider invocation itself remains bound to existing ``ModelRequest`` and
    ``ModelCallResult`` contracts.
    """

    def discover(
        self,
        *,
        request: ModelRequest,
        tools: RepositoryToolSession,
    ) -> ModelNativeDiscoveryPayload: ...


@dataclass(frozen=True, slots=True)
class ModelNativeDiscoveryPlan:
    """Trusted, immutable selectors and budgets for exactly one discovery node."""

    receipt_id: str
    request: ModelRequest
    preflight_eligibility: PreflightEligibility
    scope: RepositoryToolScope
    tool_budget: RepositoryToolBudget
    producer: ProducerRef

    def __post_init__(self) -> None:
        if (
            type(self.receipt_id) is not str
            or _ID.fullmatch(self.receipt_id) is None
            or type(self.request) is not ModelRequest
            or type(self.preflight_eligibility) is not PreflightEligibility
            or type(self.scope) is not RepositoryToolScope
            or type(self.tool_budget) is not RepositoryToolBudget
            or type(self.producer) is not ProducerRef
        ):
            raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.INVALID_REQUEST)
        if (
            self.request.role is not ModelRole.DISCOVERY
            or self.request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or self.request.evidence
            or self.scope.tenant_id != self.request.tenant_id
            or (
                self.scope.repository_id
                != self.request.execution_identity.repository_revision.repository_id
            )
            or self.scope.head_sha != self.request.head_sha
            or not self.scope.path_prefixes
            or self.tool_budget.max_calls > self.request.budget.max_repository_calls
            or self.tool_budget.max_bytes > self.request.budget.max_context_bytes
            or self.tool_budget.max_tokens > self.request.budget.max_input_tokens
        ):
            raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.IDENTITY_MISMATCH)

    @property
    def scope_sha256(self) -> str:
        return _sha256(
            _canonical_bytes(
                {
                    "evidence_ids": list(self.scope.evidence_ids),
                    "head_sha": self.scope.head_sha,
                    "path_prefixes": list(self.scope.path_prefixes),
                    "repository_id": self.scope.repository_id,
                    "tenant_id": self.scope.tenant_id,
                }
            )
        )

    @property
    def input_sha256(self) -> str:
        """Hash semantic selectors only; source/tool content is intentionally absent."""

        return _sha256(
            _canonical_bytes(
                {
                    "model_request": self.request.model_dump(mode="json"),
                    "producer": self.producer.model_dump(mode="json"),
                    "scope_sha256": self.scope_sha256,
                    "tool_budget": {
                        "max_bytes": self.tool_budget.max_bytes,
                        "max_calls": self.tool_budget.max_calls,
                        "max_tokens": self.tool_budget.max_tokens,
                    },
                }
            )
        )


class RepositoryToolSession:
    """The sole model-visible repository capability for one discovery attempt."""

    __slots__ = ("_backend", "_guard", "_receipts")

    def __init__(self, *, guard: RepositoryToolGuard, backend: RepositoryView) -> None:
        self._guard = guard
        self._backend = backend
        self._receipts: list[RepositoryToolReceipt] = []

    def dispatch(self, request: object) -> GuardedToolResult:
        """Dispatch one typed request and retain only its source-free receipt."""

        result = self._guard.dispatch(request, self._backend)
        self._receipts.append(result.receipt)
        return result

    @property
    def receipts(self) -> tuple[RepositoryToolReceipt, ...]:
        return tuple(self._receipts)

    @property
    def call_hashes(self) -> tuple[str, ...]:
        return tuple(_receipt_sha256(item) for item in self._receipts)

    @property
    def calls_used(self) -> int:
        return sum(1 for item in self._receipts if item.decision.value == "ALLOW")

    @property
    def has_non_success(self) -> bool:
        return any(item.outcome is not ToolOutcome.SUCCEEDED for item in self._receipts)

    @property
    def failure_status(self) -> ModelCallStatus:
        if any(item.reason is ToolReason.BUDGET_EXHAUSTED for item in self._receipts):
            return ModelCallStatus.BUDGET_EXHAUSTED
        return ModelCallStatus.GUARDRAIL_BLOCKED


@dataclass(frozen=True, slots=True)
class ModelNativeDiscoveryOutcome:
    """Typed output for one mandatory lane; it never implies a product PASS."""

    receipt: ModelDiscoveryReceipt
    candidates: tuple[DiscoveryCandidate, ...]
    tool_receipts: tuple[RepositoryToolReceipt, ...]
    required_terminal_outcome: AuditRunOutcome | None

    def __post_init__(self) -> None:
        if (
            type(self.receipt) is not ModelDiscoveryReceipt
            or type(self.candidates) is not tuple
            or any(type(item) is not DiscoveryCandidate for item in self.candidates)
            or type(self.tool_receipts) is not tuple
            or any(type(item) is not RepositoryToolReceipt for item in self.tool_receipts)
            or self.receipt.candidate_ids != tuple(item.candidate_id for item in self.candidates)
            or (
                self.receipt.model_call_status is ModelCallStatus.SUCCEEDED
                and self.required_terminal_outcome is not None
            )
            or (
                self.receipt.model_call_status is not ModelCallStatus.SUCCEEDED
                and (
                    self.candidates
                    or self.required_terminal_outcome is not AuditRunOutcome.INDETERMINATE
                )
            )
        ):
            raise ModelNativeDiscoveryError(ModelNativeDiscoveryErrorCode.INTEGRITY_FAILURE)

    @property
    def is_completed_zero(self) -> bool:
        return self.receipt.is_completed_zero


def _lineage_id(plan: ModelNativeDiscoveryPlan, draft: ModelNativeCandidateDraft) -> str:
    return "lineage:" + _sha256(
        _canonical_bytes(
            {
                "candidate_id": draft.candidate_id,
                "candidate_version": draft.candidate_version,
                "head_sha": plan.request.head_sha,
                "producer": plan.producer.model_dump(mode="json"),
                "source_id": draft.source_id,
            }
        )
    )


def _payload_sha256(
    candidates: tuple[ModelNativeCandidateDraft, ...], call_hashes: tuple[str, ...]
) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "candidates": [
                    {
                        "candidate_id": item.candidate_id,
                        "candidate_version": item.candidate_version,
                        "evidence_ids": list(item.evidence_ids),
                        "root_cause_fingerprint": item.root_cause_fingerprint,
                        "source_id": item.source_id,
                    }
                    for item in candidates
                ],
                "repository_view_call_hashes": list(call_hashes),
            }
        )
    )


def _receipt_sha256(receipt: RepositoryToolReceipt) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "bytes_used": receipt.bytes_used,
                "calls_used": receipt.calls_used,
                "decision": receipt.decision.value,
                "outcome": receipt.outcome.value,
                "output_sha256": receipt.output_sha256,
                "reason": receipt.reason.value,
                "sequence": receipt.sequence,
                "tokens_used": receipt.tokens_used,
                "tool": receipt.tool,
            }
        )
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
