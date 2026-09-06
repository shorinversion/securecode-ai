"""Metadata-only semantic diff and blast-radius classification for P4 repairs.

The reviewer consumes the Architect's already bounded symbol receipt and a
validated sandbox result.  It never opens the diff artifact, source tree, or
any execution capability; a completed review is deliberately not an approval.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Final

from securecode_ai.contracts import (
    PatchCandidate,
    ValidationGateOutcome,
    ValidationOutcome,
    ValidationResult,
)

from .architect import ArchitectPatchResult, PatchRationaleReceipt, TouchedSymbol

_SCHEMA_VERSION: Final = "1.0.0"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_SYMBOLS: Final = 256
_PROTECTED_PREFIXES: Final = (
    ".git",
    "artifacts/gates",
    ".github",
    "docs",
    "packages/contracts",
    "scripts",
    "specs",
    "work/task-packets",
)
_KNOWN_SYMBOL_KINDS: Final = frozenset(
    {"module", "class", "function", "async_function", "method", "async_method"}
)
_RISK_TOKENS: Final = {
    "AUTHENTICATION": frozenset({"auth", "login", "session", "token", "credential"}),
    "AUTHORIZATION": frozenset({"authorize", "permission", "role", "acl", "policy"}),
    "PUBLIC_API": frozenset({"api", "endpoint", "route", "handler", "public"}),
    "CRYPTOGRAPHY": frozenset(
        {"crypto", "cipher", "encrypt", "decrypt", "signature", "tls", "key"}
    ),
}


class DiffReviewErrorCode(StrEnum):
    """Closed request failures which are safe to surface to later policy."""

    REQUEST_INVALID = "REQUEST_INVALID"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class DiffReviewError(ValueError):
    """A fixed boundary error that never renders diff or source text."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: DiffReviewErrorCode) -> None:
        if type(code) is not DiffReviewErrorCode:
            raise TypeError("diff review error code is invalid")
        self.code = code
        self.safe_message = "semantic diff review validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class SemanticRiskArea(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    PUBLIC_API = "PUBLIC_API"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class BlastRadius(StrEnum):
    LOCALIZED = "LOCALIZED"
    CROSS_MODULE = "CROSS_MODULE"
    UNKNOWN = "UNKNOWN"


class DiffReviewDisposition(StrEnum):
    """A review classification, never a patch status or an approval decision."""

    REVIEWED_NO_HUMAN_MARKER = "REVIEWED_NO_HUMAN_MARKER"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class DiffReviewReceipt:
    """Canonical evidence-only result for a single patch and validation receipt."""

    patch_id: str
    finding_id: str
    tenant_id: str
    repository_id: str
    parent_head_sha: str
    validated_head_sha: str
    unified_diff_sha256: str
    validation_id: str
    validation_result_sha256: str
    rationale_sha256: str
    root_cause_id: str
    invariant_id: str
    invariant_version: str
    regression_descriptor_id: str
    touched_symbol_count: int
    risk_areas: tuple[SemanticRiskArea, ...]
    blast_radius: BlastRadius
    disposition: DiffReviewDisposition
    human_required: bool
    approval_eligible: bool
    review_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.patch_id,
                    self.finding_id,
                    self.tenant_id,
                    self.repository_id,
                    self.validation_id,
                    self.root_cause_id,
                    self.invariant_id,
                    self.invariant_version,
                    self.regression_descriptor_id,
                )
            )
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (
                    self.unified_diff_sha256,
                    self.validation_result_sha256,
                    self.rationale_sha256,
                    self.review_sha256,
                )
            )
            or any(
                type(value) is not str or _COMMIT_SHA.fullmatch(value) is None
                for value in (self.parent_head_sha, self.validated_head_sha)
            )
            or self.parent_head_sha == self.validated_head_sha
            or type(self.touched_symbol_count) is not int
            or not 1 <= self.touched_symbol_count <= _MAX_SYMBOLS
            or type(self.risk_areas) is not tuple
            or not self.risk_areas
            or any(type(value) is not SemanticRiskArea for value in self.risk_areas)
            or tuple(sorted(self.risk_areas, key=lambda value: value.value)) != self.risk_areas
            or len(set(self.risk_areas)) != len(self.risk_areas)
            or type(self.blast_radius) is not BlastRadius
            or type(self.disposition) is not DiffReviewDisposition
            or type(self.human_required) is not bool
            or self.human_required != (self.disposition is DiffReviewDisposition.HUMAN_REQUIRED)
            or self.approval_eligible is not False
            or self.review_sha256 != _review_hash(self)
        ):
            raise DiffReviewError(DiffReviewErrorCode.INTEGRITY_FAILURE)


def review_semantic_diff(
    architect_result: ArchitectPatchResult,
    validation: ValidationResult,
) -> DiffReviewReceipt:
    """Classify the bounded semantic surface of an already generated patch.

    Invalid identities are request failures.  A complete but non-validating
    ladder result is represented as an explicit indeterminate receipt so a
    downstream human gate cannot reinterpret it as validation success.
    """

    patch, rationale = _copy_architect(architect_result)
    checked_validation = _copy_validation(validation)
    _assert_identity(patch, rationale, checked_validation)
    risks = _classify_risks(rationale.touched_symbols)
    radius = _blast_radius(rationale.touched_symbols)
    disposition = _disposition(patch, rationale, checked_validation, risks, radius)
    return _make_receipt(patch, rationale, checked_validation, risks, radius, disposition)


def _disposition(
    patch: PatchCandidate,
    rationale: PatchRationaleReceipt,
    validation: ValidationResult,
    risks: tuple[SemanticRiskArea, ...],
    radius: BlastRadius,
) -> DiffReviewDisposition:
    del patch
    if _has_protected_path(rationale.touched_symbols):
        return DiffReviewDisposition.REJECTED
    if not _validation_passed(validation):
        return DiffReviewDisposition.INDETERMINATE
    if (
        radius is not BlastRadius.LOCALIZED
        or SemanticRiskArea.UNKNOWN in risks
        or any(
            item in risks
            for item in (
                SemanticRiskArea.AUTHENTICATION,
                SemanticRiskArea.AUTHORIZATION,
                SemanticRiskArea.PUBLIC_API,
                SemanticRiskArea.CRYPTOGRAPHY,
            )
        )
    ):
        return DiffReviewDisposition.HUMAN_REQUIRED
    return DiffReviewDisposition.REVIEWED_NO_HUMAN_MARKER


def _classify_risks(symbols: tuple[TouchedSymbol, ...]) -> tuple[SemanticRiskArea, ...]:
    risks: set[SemanticRiskArea] = set()
    for symbol in symbols:
        if symbol.symbol_kind not in _KNOWN_SYMBOL_KINDS:
            risks.add(SemanticRiskArea.UNKNOWN)
            continue
        material = f"{symbol.path}/{symbol.symbol_name}".casefold()
        matched = False
        for name, tokens in _RISK_TOKENS.items():
            if any(token in material for token in tokens):
                risks.add(SemanticRiskArea(name))
                matched = True
        if not matched:
            risks.add(SemanticRiskArea.OTHER)
    return tuple(sorted(risks, key=lambda value: value.value))


def _blast_radius(symbols: tuple[TouchedSymbol, ...]) -> BlastRadius:
    paths = {item.path for item in symbols}
    if not paths:
        return BlastRadius.UNKNOWN
    return BlastRadius.LOCALIZED if len(paths) == 1 else BlastRadius.CROSS_MODULE


def _has_protected_path(symbols: tuple[TouchedSymbol, ...]) -> bool:
    for symbol in symbols:
        path = _safe_path(symbol.path)
        if path is None or any(
            path == prefix or path.startswith(prefix + "/") for prefix in _PROTECTED_PREFIXES
        ):
            return True
    return False


def _validation_passed(value: ValidationResult) -> bool:
    return value.validation_outcome is ValidationOutcome.VALIDATED and all(
        gate.gate_outcome is ValidationGateOutcome.PASSED for gate in value.gates
    )


def _assert_identity(
    patch: PatchCandidate, rationale: PatchRationaleReceipt, validation: ValidationResult
) -> None:
    revision = patch.repository_revision
    if (
        patch.finding_id != rationale.finding_id
        or validation.patch_id != patch.patch_id
        or validation.tenant_id != revision.tenant_id
        or validation.head_sha == revision.head_sha
        or patch.diff_ref.content_id != patch.patch_id
        or patch.diff_ref.content_sha256 != patch.unified_diff_sha256
    ):
        raise DiffReviewError(DiffReviewErrorCode.INTEGRITY_FAILURE)


def _copy_architect(value: ArchitectPatchResult) -> tuple[PatchCandidate, PatchRationaleReceipt]:
    if type(value) is not ArchitectPatchResult:
        raise DiffReviewError(DiffReviewErrorCode.REQUEST_INVALID)
    try:
        patch = PatchCandidate.model_validate(value.patch_candidate.model_dump(mode="python"))
        symbols = tuple(
            TouchedSymbol(
                item.path,
                item.symbol_kind,
                item.symbol_name,
                item.start_line,
                item.end_line,
                item.symbol_sha256,
            )
            for item in value.rationale.touched_symbols
        )
        rationale = PatchRationaleReceipt(
            finding_id=value.rationale.finding_id,
            root_cause_id=value.rationale.root_cause_id,
            invariant_id=value.rationale.invariant_id,
            invariant_version=value.rationale.invariant_version,
            regression_descriptor_id=value.rationale.regression_descriptor_id,
            touched_symbols=symbols,
            rationale_sha256=value.rationale.rationale_sha256,
            schema_version=value.rationale.schema_version,
        )
        return patch, rationale
    except (AttributeError, TypeError, ValueError):
        raise DiffReviewError(DiffReviewErrorCode.INTEGRITY_FAILURE) from None


def _copy_validation(value: ValidationResult) -> ValidationResult:
    if type(value) is not ValidationResult:
        raise DiffReviewError(DiffReviewErrorCode.REQUEST_INVALID)
    try:
        return ValidationResult.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise DiffReviewError(DiffReviewErrorCode.INTEGRITY_FAILURE) from None


def _safe_path(value: str) -> str | None:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or "\x00" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value) is not None
        or any(part in ("", ".", "..") for part in value.split("/"))
        or str(PurePosixPath(value)) != value
        or any(ord(char) < 32 or not char.isprintable() for char in value)
    ):
        return None
    return value


def _review_material(value: DiffReviewReceipt) -> dict[str, object]:
    return {
        "approval_eligible": value.approval_eligible,
        "blast_radius": value.blast_radius.value,
        "disposition": value.disposition.value,
        "finding_id": value.finding_id,
        "human_required": value.human_required,
        "invariant_id": value.invariant_id,
        "invariant_version": value.invariant_version,
        "parent_head_sha": value.parent_head_sha,
        "patch_id": value.patch_id,
        "rationale_sha256": value.rationale_sha256,
        "regression_descriptor_id": value.regression_descriptor_id,
        "repository_id": value.repository_id,
        "risk_areas": [item.value for item in value.risk_areas],
        "root_cause_id": value.root_cause_id,
        "schema_version": value.schema_version,
        "tenant_id": value.tenant_id,
        "touched_symbol_count": value.touched_symbol_count,
        "unified_diff_sha256": value.unified_diff_sha256,
        "validated_head_sha": value.validated_head_sha,
        "validation_id": value.validation_id,
        "validation_result_sha256": value.validation_result_sha256,
    }


def _review_hash(value: DiffReviewReceipt) -> str:
    return hashlib.sha256(
        json.dumps(
            _review_material(value),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _make_receipt(
    patch: PatchCandidate,
    rationale: PatchRationaleReceipt,
    validation: ValidationResult,
    risks: tuple[SemanticRiskArea, ...],
    radius: BlastRadius,
    disposition: DiffReviewDisposition,
) -> DiffReviewReceipt:
    seed = object.__new__(DiffReviewReceipt)
    values = {
        "patch_id": patch.patch_id,
        "finding_id": patch.finding_id,
        "tenant_id": patch.repository_revision.tenant_id,
        "repository_id": patch.repository_revision.repository_id,
        "parent_head_sha": patch.repository_revision.head_sha,
        "validated_head_sha": validation.head_sha,
        "unified_diff_sha256": patch.unified_diff_sha256,
        "validation_id": validation.validation_id,
        "validation_result_sha256": validation.result_sha256,
        "rationale_sha256": rationale.rationale_sha256,
        "root_cause_id": rationale.root_cause_id,
        "invariant_id": rationale.invariant_id,
        "invariant_version": rationale.invariant_version,
        "regression_descriptor_id": rationale.regression_descriptor_id,
        "touched_symbol_count": len(rationale.touched_symbols),
        "risk_areas": risks,
        "blast_radius": radius,
        "disposition": disposition,
        "human_required": disposition is DiffReviewDisposition.HUMAN_REQUIRED,
        "approval_eligible": False,
        "review_sha256": "0" * 64,
        "schema_version": _SCHEMA_VERSION,
    }
    for name, item in values.items():
        object.__setattr__(seed, name, item)
    return DiffReviewReceipt(
        patch_id=patch.patch_id,
        finding_id=patch.finding_id,
        tenant_id=patch.repository_revision.tenant_id,
        repository_id=patch.repository_revision.repository_id,
        parent_head_sha=patch.repository_revision.head_sha,
        validated_head_sha=validation.head_sha,
        unified_diff_sha256=patch.unified_diff_sha256,
        validation_id=validation.validation_id,
        validation_result_sha256=validation.result_sha256,
        rationale_sha256=rationale.rationale_sha256,
        root_cause_id=rationale.root_cause_id,
        invariant_id=rationale.invariant_id,
        invariant_version=rationale.invariant_version,
        regression_descriptor_id=rationale.regression_descriptor_id,
        touched_symbol_count=len(rationale.touched_symbols),
        risk_areas=risks,
        blast_radius=radius,
        disposition=disposition,
        human_required=disposition is DiffReviewDisposition.HUMAN_REQUIRED,
        approval_eligible=False,
        review_sha256=_review_hash(seed),
        schema_version=_SCHEMA_VERSION,
    )


__all__ = [
    "BlastRadius",
    "DiffReviewDisposition",
    "DiffReviewError",
    "DiffReviewErrorCode",
    "DiffReviewReceipt",
    "SemanticRiskArea",
    "review_semantic_diff",
]
