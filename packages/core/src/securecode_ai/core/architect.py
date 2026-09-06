"""Structured, source-bounded patch-candidate contract for the Architect.

This module validates a proposed unified diff and its provenance.  It never
applies a patch, executes a test, reads a repository, or grants approval.
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
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    DataClass,
    FindingCase,
    PatchCandidate,
    PatchStatus,
    ProducerRef,
)

from .regression import SecurityRegressionDescriptor
from .root_cause import RootCauseEvidenceRefs, RootCauseRecord
from .security_invariants import SecurityInvariant, evaluate_security_invariant

_SCHEMA_VERSION: Final = "1.0.0"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_DIFF_BYTES: Final = 131_072
_MAX_DIFF_LINES: Final = 4_096
_MAX_FILES: Final = 64
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


class ArchitectErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    ROOT_CAUSE_MISMATCH = "ROOT_CAUSE_MISMATCH"
    INVARIANT_MISMATCH = "INVARIANT_MISMATCH"
    REGRESSION_MISMATCH = "REGRESSION_MISMATCH"
    DIFF_INVALID = "DIFF_INVALID"
    PATH_FORBIDDEN = "PATH_FORBIDDEN"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    DIFF_TOO_LARGE = "DIFF_TOO_LARGE"
    SYMBOL_SET_INVALID = "SYMBOL_SET_INVALID"
    RATIONALE_INVALID = "RATIONALE_INVALID"


class ArchitectPatchError(ValueError):
    """Fixed, non-echoing Architect boundary error."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: ArchitectErrorCode) -> None:
        if type(code) is not ArchitectErrorCode:
            raise TypeError("architect error code is invalid")
        self.code = code
        self.safe_message = "architect patch contract validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class TouchedSymbol:
    path: str
    symbol_kind: str
    symbol_name: str
    start_line: int
    end_line: int
    symbol_sha256: str

    def __post_init__(self) -> None:
        if (
            _safe_path(self.path) is None
            or type(self.symbol_kind) is not str
            or not 1 <= len(self.symbol_kind) <= 64
            or type(self.symbol_name) is not str
            or not 1 <= len(self.symbol_name) <= 256
            or type(self.start_line) is not int
            or type(self.end_line) is not int
            or self.start_line < 1
            or self.end_line < self.start_line
            or self.end_line - self.start_line > 100_000
            or _SHA256.fullmatch(self.symbol_sha256) is None
        ):
            raise ArchitectPatchError(ArchitectErrorCode.SYMBOL_SET_INVALID)


@dataclass(frozen=True, slots=True)
class PatchRationaleReceipt:
    finding_id: str
    root_cause_id: str
    invariant_id: str
    invariant_version: str
    regression_descriptor_id: str
    touched_symbols: tuple[TouchedSymbol, ...]
    rationale_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(
                _ID.fullmatch(value) is None
                for value in (
                    self.finding_id,
                    self.root_cause_id,
                    self.invariant_id,
                    self.invariant_version,
                    self.regression_descriptor_id,
                )
            )
            or type(self.touched_symbols) is not tuple
            or not 1 <= len(self.touched_symbols) <= _MAX_SYMBOLS
            or any(type(value) is not TouchedSymbol for value in self.touched_symbols)
            or tuple(
                sorted(
                    self.touched_symbols,
                    key=lambda value: (value.path, value.start_line, value.symbol_name),
                )
            )
            != self.touched_symbols
            or _SHA256.fullmatch(self.rationale_sha256) is None
            or self.rationale_sha256 != _rationale_hash(self)
        ):
            raise ArchitectPatchError(ArchitectErrorCode.RATIONALE_INVALID)


@dataclass(frozen=True, slots=True)
class ArchitectPatchResult:
    patch_candidate: PatchCandidate
    rationale: PatchRationaleReceipt

    def __post_init__(self) -> None:
        if (
            type(self.patch_candidate) is not PatchCandidate
            or type(self.rationale) is not PatchRationaleReceipt
            or self.patch_candidate.finding_id != self.rationale.finding_id
        ):
            raise ArchitectPatchError(ArchitectErrorCode.REQUEST_INVALID)


def emit_patch_candidate(
    finding: FindingCase,
    root_cause: RootCauseRecord,
    invariant: SecurityInvariant,
    regression: SecurityRegressionDescriptor,
    *,
    unified_diff: str,
    rationale: str,
    touched_symbols: tuple[TouchedSymbol, ...],
    author: ProducerRef,
) -> ArchitectPatchResult:
    """Validate and package one suggested patch; never apply or approve it."""

    checked_finding = _copy_finding(finding)
    checked_root = _copy_root(root_cause)
    checked_invariant = _copy_invariant(invariant)
    checked_regression = _copy_regression(regression)
    if type(author) is not ProducerRef:
        raise ArchitectPatchError(ArchitectErrorCode.REQUEST_INVALID)
    revision = checked_finding.repository_revision
    if (
        checked_finding.finding_id != checked_root.finding_id
        or checked_finding.finding_id != checked_invariant.finding_id
        or checked_root.record_id != checked_invariant.root_cause_id
        or checked_root.record_id != checked_regression.root_cause_id
        or checked_finding.finding_id != checked_regression.finding_id
        or revision.tenant_id != checked_root.tenant_id != checked_regression.tenant_id
        or revision.repository_id != checked_root.repository_id != checked_regression.repository_id
        or revision.head_sha != checked_root.head_sha
        or checked_regression.vulnerable_head_sha != checked_root.head_sha
        or revision.head_sha != checked_invariant.head_sha
        or checked_root.root_cause_fingerprint != checked_invariant.root_cause_fingerprint
        or checked_regression.root_cause_fingerprint != checked_root.root_cause_fingerprint
        or not evaluate_security_invariant(checked_invariant, checked_root).satisfied
        or checked_regression.invariant_id != checked_invariant.invariant_id
        or checked_regression.invariant_version != checked_invariant.invariant_version
        or checked_regression.invariant_sha256 != checked_invariant.invariant_sha256
    ):
        raise ArchitectPatchError(ArchitectErrorCode.IDENTITY_MISMATCH)
    if type(unified_diff) is not str or type(rationale) is not str:
        raise ArchitectPatchError(ArchitectErrorCode.REQUEST_INVALID)
    if not rationale.strip() or len(rationale) > 4096:
        raise ArchitectPatchError(ArchitectErrorCode.RATIONALE_INVALID)
    diff_bytes = unified_diff.encode("utf-8", errors="strict")
    paths = _validate_diff(unified_diff, len(diff_bytes))
    symbols = _validate_symbols(touched_symbols, paths)
    rationale_receipt = _make_rationale(
        finding_id=checked_finding.finding_id,
        root_cause_id=checked_root.record_id,
        invariant_id=checked_invariant.invariant_id,
        invariant_version=checked_invariant.invariant_version,
        regression_descriptor_id=checked_regression.descriptor_id,
        touched_symbols=symbols,
    )
    diff_hash = hashlib.sha256(diff_bytes).hexdigest()
    patch_id = f"patch-{diff_hash}"
    diff_ref = ArtifactRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id=revision.tenant_id,
        content_id=patch_id,
        content_sha256=diff_hash,
        size_bytes=len(diff_bytes),
        data_class=DataClass.CONFIDENTIAL_SOURCE,
    )
    patch = PatchCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        patch_id=patch_id,
        finding_id=checked_finding.finding_id,
        repository_revision=revision,
        unified_diff_sha256=diff_hash,
        diff_ref=diff_ref,
        author=author,
        patch_status=PatchStatus.SUGGESTED,
    )
    return ArchitectPatchResult(patch, rationale_receipt)


def _validate_diff(value: str, size: int) -> tuple[str, ...]:
    if size < 1 or size > _MAX_DIFF_BYTES:
        raise ArchitectPatchError(ArchitectErrorCode.DIFF_TOO_LARGE)
    lines = value.splitlines()
    if len(lines) > _MAX_DIFF_LINES or not lines:
        raise ArchitectPatchError(ArchitectErrorCode.DIFF_TOO_LARGE)
    paths: set[str] = set()
    saw_hunk = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff --git "):
            parts = line.split(" ")
            if len(parts) != 4:
                raise ArchitectPatchError(ArchitectErrorCode.DIFF_INVALID)
        if line.startswith("--- "):
            if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                raise ArchitectPatchError(ArchitectErrorCode.DIFF_INVALID)
            old = _diff_path(lines[index][4:])
            new = _diff_path(lines[index + 1][4:])
            if old is None and new is None:
                raise ArchitectPatchError(ArchitectErrorCode.DIFF_INVALID)
            for path in (old, new):
                if path is not None:
                    paths.add(path)
            index += 1
        if line.startswith("@@ "):
            saw_hunk = True
        if "\x00" in line or "GIT binary patch" in line:
            raise ArchitectPatchError(ArchitectErrorCode.DIFF_INVALID)
        index += 1
    if not saw_hunk or not paths or len(paths) > _MAX_FILES:
        raise ArchitectPatchError(ArchitectErrorCode.DIFF_INVALID)
    return tuple(sorted(paths))


def _diff_path(value: str) -> str | None:
    path = value.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    safe = _safe_path(path)
    if safe is None:
        raise ArchitectPatchError(ArchitectErrorCode.PATH_TRAVERSAL)
    if any(safe == prefix or safe.startswith(prefix + "/") for prefix in _PROTECTED_PREFIXES):
        raise ArchitectPatchError(ArchitectErrorCode.PATH_FORBIDDEN)
    return safe


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


def _validate_symbols(
    values: tuple[TouchedSymbol, ...], paths: tuple[str, ...]
) -> tuple[TouchedSymbol, ...]:
    if type(values) is not tuple or not values or len(values) > _MAX_SYMBOLS:
        raise ArchitectPatchError(ArchitectErrorCode.SYMBOL_SET_INVALID)
    try:
        copied = tuple(
            TouchedSymbol(
                item.path,
                item.symbol_kind,
                item.symbol_name,
                item.start_line,
                item.end_line,
                item.symbol_sha256,
            )
            for item in values
        )
    except (AttributeError, TypeError, ValueError):
        raise ArchitectPatchError(ArchitectErrorCode.SYMBOL_SET_INVALID) from None
    ordered = tuple(
        sorted(copied, key=lambda value: (value.path, value.start_line, value.symbol_name))
    )
    if ordered != copied or len(
        {(item.path, item.symbol_name, item.start_line) for item in copied}
    ) != len(copied):
        raise ArchitectPatchError(ArchitectErrorCode.SYMBOL_SET_INVALID)
    if any(item.path not in paths for item in copied):
        raise ArchitectPatchError(ArchitectErrorCode.SYMBOL_SET_INVALID)
    return copied


def _copy_finding(value: FindingCase) -> FindingCase:
    if type(value) is not FindingCase:
        raise ArchitectPatchError(ArchitectErrorCode.REQUEST_INVALID)
    try:
        return FindingCase.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise ArchitectPatchError(ArchitectErrorCode.REQUEST_INVALID) from None


def _copy_root(value: RootCauseRecord) -> RootCauseRecord:
    if type(value) is not RootCauseRecord:
        raise ArchitectPatchError(ArchitectErrorCode.ROOT_CAUSE_MISMATCH)
    try:
        return RootCauseRecord(
            record_id=value.record_id,
            schema_version=value.schema_version,
            finding_id=value.finding_id,
            candidate_id=value.candidate_id,
            candidate_version=value.candidate_version,
            tenant_id=value.tenant_id,
            repository_id=value.repository_id,
            head_sha=value.head_sha,
            root_cause_fingerprint=value.root_cause_fingerprint,
            evidence_graph_id=value.evidence_graph_id,
            evidence_graph_sha256=value.evidence_graph_sha256,
            evidence=RootCauseEvidenceRefs(
                value.evidence.source_evidence_id,
                value.evidence.propagation_evidence_id,
                value.evidence.sink_evidence_id,
            ),
        )
    except (AttributeError, TypeError, ValueError):
        raise ArchitectPatchError(ArchitectErrorCode.ROOT_CAUSE_MISMATCH) from None


def _copy_invariant(value: SecurityInvariant) -> SecurityInvariant:
    if type(value) is not SecurityInvariant:
        raise ArchitectPatchError(ArchitectErrorCode.INVARIANT_MISMATCH)
    try:
        return SecurityInvariant(
            **{name: getattr(value, name) for name in SecurityInvariant.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise ArchitectPatchError(ArchitectErrorCode.INVARIANT_MISMATCH) from None


def _copy_regression(value: SecurityRegressionDescriptor) -> SecurityRegressionDescriptor:
    if type(value) is not SecurityRegressionDescriptor:
        raise ArchitectPatchError(ArchitectErrorCode.REGRESSION_MISMATCH)
    try:
        return SecurityRegressionDescriptor(
            **{
                name: getattr(value, name)
                for name in SecurityRegressionDescriptor.__dataclass_fields__
            }
        )
    except (AttributeError, TypeError, ValueError):
        raise ArchitectPatchError(ArchitectErrorCode.REGRESSION_MISMATCH) from None


def _rationale_material(value: PatchRationaleReceipt) -> dict[str, object]:
    return {
        "finding_id": value.finding_id,
        "root_cause_id": value.root_cause_id,
        "invariant_id": value.invariant_id,
        "invariant_version": value.invariant_version,
        "regression_descriptor_id": value.regression_descriptor_id,
        "schema_version": value.schema_version,
        "touched_symbols": [
            {
                "path": item.path,
                "symbol_kind": item.symbol_kind,
                "symbol_name": item.symbol_name,
                "start_line": item.start_line,
                "end_line": item.end_line,
                "symbol_sha256": item.symbol_sha256,
            }
            for item in value.touched_symbols
        ],
    }


def _rationale_hash(value: PatchRationaleReceipt) -> str:
    return hashlib.sha256(
        json.dumps(
            _rationale_material(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _make_rationale(**values: object) -> PatchRationaleReceipt:
    seed = object.__new__(PatchRationaleReceipt)
    for name, value in values.items():
        object.__setattr__(seed, name, value)
    object.__setattr__(seed, "schema_version", _SCHEMA_VERSION)
    object.__setattr__(seed, "rationale_sha256", "0" * 64)
    return PatchRationaleReceipt(
        finding_id=seed.finding_id,
        root_cause_id=seed.root_cause_id,
        invariant_id=seed.invariant_id,
        invariant_version=seed.invariant_version,
        regression_descriptor_id=seed.regression_descriptor_id,
        touched_symbols=seed.touched_symbols,
        rationale_sha256=_rationale_hash(seed),
        schema_version=seed.schema_version,
    )


__all__ = [
    "ArchitectErrorCode",
    "ArchitectPatchError",
    "ArchitectPatchResult",
    "PatchRationaleReceipt",
    "TouchedSymbol",
    "emit_patch_candidate",
]
