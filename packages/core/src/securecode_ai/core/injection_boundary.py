"""Structural trust boundary for repository and other untrusted text.

This module deliberately does not try to classify prompt injections.  Text that
looks like an instruction remains data, whether it is direct, encoded, split
between records, or returned by a tool/provider.  The trusted control plane is
constructed separately and no untrusted-text API accepts a policy, tool,
budget, route, provider, destination, or coverage selector.

The boundary is a process-local structural safeguard, not a Python sandbox.
Callers must still keep the returned text out of trusted instructions and use
the later P3 tool-policy and routing boundaries for effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER: Final = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_MAX_SPANS: Final = 1_024
_MAX_SPAN_BYTES: Final = 131_072
_MAX_TOTAL_BYTES: Final = 1_048_576


class InstructionAuthority(StrEnum):
    """The only authority label available for untrusted text."""

    NONE = "NONE"


class UntrustedTextOrigin(StrEnum):
    """Closed origin labels that must remain untrusted through investigation."""

    REPOSITORY_SOURCE = "REPOSITORY_SOURCE"
    REPOSITORY_COMMENT = "REPOSITORY_COMMENT"
    REPOSITORY_IDENTIFIER = "REPOSITORY_IDENTIFIER"
    REPOSITORY_DOCUMENTATION = "REPOSITORY_DOCUMENTATION"
    SCM_METADATA = "SCM_METADATA"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    MODEL_REFUSAL = "MODEL_REFUSAL"


class BoundaryAdmissionStatus(StrEnum):
    """Closed non-success-aware admission outcomes."""

    ADMITTED = "ADMITTED"
    REJECTED = "REJECTED"


class BoundaryRejectionCode(StrEnum):
    """Fixed, non-echoing reasons for a denied boundary operation."""

    INVALID_REQUEST = "INVALID_REQUEST"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    CONTROL_MUTATION_DENIED = "CONTROL_MUTATION_DENIED"


class InjectionBoundaryError(ValueError):
    """Typed non-echoing failure raised only for invalid trusted construction."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: BoundaryRejectionCode) -> None:
        if type(code) is not BoundaryRejectionCode:
            raise TypeError("injection-boundary error code is invalid")
        self.code = code
        self.safe_message = "untrusted text boundary rejected input"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class InvestigationBudget:
    """Host-selected, immutable limits which untrusted data cannot select."""

    max_context_bytes: int
    max_tool_calls: int
    max_iterations: int

    def __post_init__(self) -> None:
        if (
            type(self.max_context_bytes) is not int
            or type(self.max_tool_calls) is not int
            or type(self.max_iterations) is not int
            or not 1 <= self.max_context_bytes <= _MAX_TOTAL_BYTES
            or not 0 <= self.max_tool_calls <= 1_024
            or not 0 <= self.max_iterations <= 128
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class TrustedInvestigationControls:
    """A complete, source-free control plane selected before untrusted admission."""

    policy_id: str
    policy_version: str
    policy_sha256: str
    tool_policy_id: str
    tool_policy_sha256: str
    routing_policy_id: str
    routing_policy_sha256: str
    provider_profile_id: str
    destination_id: str
    coverage_policy_id: str
    coverage_policy_sha256: str
    budget: InvestigationBudget

    def __post_init__(self) -> None:
        identifiers = (
            self.policy_id,
            self.tool_policy_id,
            self.routing_policy_id,
            self.provider_profile_id,
            self.destination_id,
            self.coverage_policy_id,
        )
        hashes = (
            self.policy_sha256,
            self.tool_policy_sha256,
            self.routing_policy_sha256,
            self.coverage_policy_sha256,
        )
        if (
            any(
                type(value) is not str or _IDENTIFIER.fullmatch(value) is None
                for value in identifiers
            )
            or type(self.policy_version) is not str
            or _SEMVER.fullmatch(self.policy_version) is None
            or any(type(value) is not str or _SHA256.fullmatch(value) is None for value in hashes)
            or type(self.budget) is not InvestigationBudget
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INVALID_REQUEST)

    @property
    def control_sha256(self) -> str:
        """Stable identity of trusted selectors and numeric limits only."""

        return _sha256(_canonical_bytes(self._material()))

    def _material(self) -> dict[str, object]:
        return {
            "budget": {
                "max_context_bytes": self.budget.max_context_bytes,
                "max_iterations": self.budget.max_iterations,
                "max_tool_calls": self.budget.max_tool_calls,
            },
            "coverage_policy_id": self.coverage_policy_id,
            "coverage_policy_sha256": self.coverage_policy_sha256,
            "destination_id": self.destination_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "provider_profile_id": self.provider_profile_id,
            "routing_policy_id": self.routing_policy_id,
            "routing_policy_sha256": self.routing_policy_sha256,
            "tool_policy_id": self.tool_policy_id,
            "tool_policy_sha256": self.tool_policy_sha256,
        }


@dataclass(frozen=True, slots=True)
class UntrustedTextSpan:
    """Opaque-labelled text data retained for later bounded context selection.

    ``text`` is intentionally never copied to an admission receipt.  Its origin
    label is fixed to ``NONE`` and is checked again on boundary admission.
    """

    span_id: str
    origin: UntrustedTextOrigin
    text: str
    instruction_authority: InstructionAuthority = InstructionAuthority.NONE

    def __post_init__(self) -> None:
        if (
            type(self.span_id) is not str
            or _IDENTIFIER.fullmatch(self.span_id) is None
            or type(self.origin) is not UntrustedTextOrigin
            or type(self.text) is not str
            or type(self.instruction_authority) is not InstructionAuthority
            or self.instruction_authority is not InstructionAuthority.NONE
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INVALID_REQUEST)

    @property
    def content_sha256(self) -> str:
        """Hash exact UTF-8 data without including it in safe metadata."""

        return _sha256(self.text.encode("utf-8"))

    @property
    def byte_count(self) -> int:
        """The retained UTF-8 byte count, not a character approximation."""

        return len(self.text.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class SafeSpanReceipt:
    """Source-free metadata for one admitted untrusted span."""

    span_id: str
    origin: UntrustedTextOrigin
    instruction_authority: InstructionAuthority
    content_sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if (
            type(self.span_id) is not str
            or _IDENTIFIER.fullmatch(self.span_id) is None
            or type(self.origin) is not UntrustedTextOrigin
            or type(self.instruction_authority) is not InstructionAuthority
            or self.instruction_authority is not InstructionAuthority.NONE
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or type(self.byte_count) is not int
            or not 0 <= self.byte_count <= _MAX_SPAN_BYTES
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INTEGRITY_FAILURE)

    def _material(self) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "content_sha256": self.content_sha256,
            "instruction_authority": self.instruction_authority.value,
            "origin": self.origin.value,
            "span_id": self.span_id,
        }


@dataclass(frozen=True, slots=True)
class InjectionBoundaryReceipt:
    """Safe, canonical receipt; it never serializes text, paths, or mutation content."""

    status: BoundaryAdmissionStatus
    rejection_code: BoundaryRejectionCode | None
    control_sha256: str
    span_receipts: tuple[SafeSpanReceipt, ...]
    total_bytes: int
    receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.status) is not BoundaryAdmissionStatus
            or (self.status is BoundaryAdmissionStatus.ADMITTED) != (self.rejection_code is None)
            or (
                self.status is BoundaryAdmissionStatus.REJECTED
                and type(self.rejection_code) is not BoundaryRejectionCode
            )
            or type(self.control_sha256) is not str
            or _SHA256.fullmatch(self.control_sha256) is None
            or type(self.span_receipts) is not tuple
            or any(type(item) is not SafeSpanReceipt for item in self.span_receipts)
            or type(self.total_bytes) is not int
            or not 0 <= self.total_bytes <= _MAX_TOTAL_BYTES
            or type(self.receipt_sha256) is not str
            or _SHA256.fullmatch(self.receipt_sha256) is None
            or self.receipt_sha256 != _sha256(_canonical_bytes(self._material()))
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INTEGRITY_FAILURE)

    def _material(self) -> dict[str, object]:
        return {
            "control_sha256": self.control_sha256,
            "rejection_code": self.rejection_code.value
            if self.rejection_code is not None
            else None,
            "span_receipts": [item._material() for item in self.span_receipts],
            "status": self.status.value,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class BoundaryAdmission:
    """Successful result coupling retained data to its safe immutable receipt."""

    controls: TrustedInvestigationControls
    spans: tuple[UntrustedTextSpan, ...]
    receipt: InjectionBoundaryReceipt

    def __post_init__(self) -> None:
        if (
            type(self.controls) is not TrustedInvestigationControls
            or type(self.spans) is not tuple
            or len(self.spans) > _MAX_SPANS
            or any(type(item) is not UntrustedTextSpan for item in self.spans)
            or type(self.receipt) is not InjectionBoundaryReceipt
            or self.receipt.status is not BoundaryAdmissionStatus.ADMITTED
            or self.receipt.control_sha256 != self.controls.control_sha256
            or self.receipt.total_bytes > self.controls.budget.max_context_bytes
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INTEGRITY_FAILURE)
        expected = tuple(_safe_span_receipt(item) for item in self.spans)
        if self.receipt.span_receipts != expected or self.receipt.total_bytes != sum(
            item.byte_count for item in self.spans
        ):
            raise InjectionBoundaryError(BoundaryRejectionCode.INTEGRITY_FAILURE)


class UntrustedTextBoundary:
    """Host-owned admission facade with no untrusted control-plane parameters."""

    __slots__ = ("_controls",)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_controls" and hasattr(self, "_controls"):
            raise AttributeError("untrusted text boundary controls are immutable")
        object.__setattr__(self, name, value)

    def __init__(self, controls: TrustedInvestigationControls) -> None:
        if type(controls) is not TrustedInvestigationControls:
            raise InjectionBoundaryError(BoundaryRejectionCode.INVALID_REQUEST)
        self._controls = controls

    @property
    def controls(self) -> TrustedInvestigationControls:
        """Return the immutable host-selected controls, never data-derived controls."""

        return self._controls

    def admit(
        self, spans: tuple[UntrustedTextSpan, ...]
    ) -> BoundaryAdmission | InjectionBoundaryReceipt:
        """Admit only an exact bounded tuple of ``NONE``-authority spans.

        An invalid input is represented by a typed safe rejection instead of an
        exception that could echo untrusted content.  The caller receives no
        partially admitted text on any rejection.
        """

        if type(spans) is not tuple:
            return self._rejection(BoundaryRejectionCode.INVALID_REQUEST)
        if len(spans) > _MAX_SPANS:
            return self._rejection(BoundaryRejectionCode.RESOURCE_LIMIT)
        if any(type(item) is not UntrustedTextSpan for item in spans):
            return self._rejection(BoundaryRejectionCode.INVALID_REQUEST)
        # UTF-8 byte length is never smaller than the Python character count.
        # Reject obviously oversized spans before encoding or hashing their
        # contents, keeping admission work bounded for hostile inputs.
        character_counts = tuple(len(item.text) for item in spans)
        if any(count > _MAX_SPAN_BYTES for count in character_counts):
            return self._rejection(BoundaryRejectionCode.RESOURCE_LIMIT)
        if sum(character_counts) > self._controls.budget.max_context_bytes:
            return self._rejection(BoundaryRejectionCode.RESOURCE_LIMIT)
        span_ids = tuple(item.span_id for item in spans)
        if len(set(span_ids)) != len(span_ids):
            return self._rejection(BoundaryRejectionCode.INTEGRITY_FAILURE)
        try:
            safe_spans = tuple(_safe_span_receipt(item) for item in spans)
        except (TypeError, ValueError, UnicodeError):
            return self._rejection(BoundaryRejectionCode.INTEGRITY_FAILURE)
        total_bytes = sum(item.byte_count for item in spans)
        if total_bytes > self._controls.budget.max_context_bytes:
            return self._rejection(BoundaryRejectionCode.RESOURCE_LIMIT)
        receipt = _receipt(
            status=BoundaryAdmissionStatus.ADMITTED,
            rejection_code=None,
            control_sha256=self._controls.control_sha256,
            span_receipts=safe_spans,
            total_bytes=total_bytes,
        )
        return BoundaryAdmission(controls=self._controls, spans=spans, receipt=receipt)

    def deny_control_mutation(self) -> InjectionBoundaryReceipt:
        """Record a source-free denial for any text-originated escalation attempt.

        No argument is accepted on purpose: retaining an attempted instruction,
        selector, encoded payload, or secret-like text in the receipt would
        itself weaken the boundary.
        """

        return self._rejection(BoundaryRejectionCode.CONTROL_MUTATION_DENIED)

    def _rejection(self, code: BoundaryRejectionCode) -> InjectionBoundaryReceipt:
        return _receipt(
            status=BoundaryAdmissionStatus.REJECTED,
            rejection_code=code,
            control_sha256=self._controls.control_sha256,
            span_receipts=(),
            total_bytes=0,
        )


def _safe_span_receipt(span: UntrustedTextSpan) -> SafeSpanReceipt:
    if (
        type(span) is not UntrustedTextSpan
        or span.instruction_authority is not InstructionAuthority.NONE
        or span.byte_count > _MAX_SPAN_BYTES
    ):
        raise InjectionBoundaryError(BoundaryRejectionCode.INTEGRITY_FAILURE)
    return SafeSpanReceipt(
        span_id=_opaque_span_id(span),
        origin=span.origin,
        instruction_authority=span.instruction_authority,
        content_sha256=span.content_sha256,
        byte_count=span.byte_count,
    )


def _opaque_span_id(span: UntrustedTextSpan) -> str:
    """Derive a receipt-local reference without serializing caller identifiers.

    Callers may use source paths or SCM text to name their in-memory spans.
    Those names must not reach a safe receipt, so only a domain-separated
    digest-derived reference leaves the boundary.
    """

    material = {
        "content_sha256": span.content_sha256,
        "origin": span.origin.value,
        "span_id": span.span_id,
    }
    return "span:" + _sha256(_canonical_bytes(material))


def _receipt(
    *,
    status: BoundaryAdmissionStatus,
    rejection_code: BoundaryRejectionCode | None,
    control_sha256: str,
    span_receipts: tuple[SafeSpanReceipt, ...],
    total_bytes: int,
) -> InjectionBoundaryReceipt:
    material = {
        "control_sha256": control_sha256,
        "rejection_code": rejection_code.value if rejection_code is not None else None,
        "span_receipts": [item._material() for item in span_receipts],
        "status": status.value,
        "total_bytes": total_bytes,
    }
    return InjectionBoundaryReceipt(
        status=status,
        rejection_code=rejection_code,
        control_sha256=control_sha256,
        span_receipts=span_receipts,
        total_bytes=total_bytes,
        receipt_sha256=_sha256(_canonical_bytes(material)),
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


__all__ = [
    "BoundaryAdmission",
    "BoundaryAdmissionStatus",
    "BoundaryRejectionCode",
    "InjectionBoundaryError",
    "InjectionBoundaryReceipt",
    "InstructionAuthority",
    "InvestigationBudget",
    "SafeSpanReceipt",
    "TrustedInvestigationControls",
    "UntrustedTextBoundary",
    "UntrustedTextOrigin",
    "UntrustedTextSpan",
]
