"""Content-addressed storage for local patch suggestions.

Patch bytes are stored outside the inspected checkout.  The adjacent manifest
contains only source-free Core contract values and is revalidated by rebuilding
the :class:`ArchitectPatchResult` on every read.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

from securecode_ai.contracts import CommandOperationEvidence, FindingCase, ProducerRef
from securecode_ai.core.architect import (
    ArchitectPatchResult,
    PatchRationaleReceipt,
    TouchedSymbol,
    emit_patch_candidate,
)
from securecode_ai.core.regression import (
    RegressionCase,
    RegressionCaseKind,
    SecurityRegressionDescriptor,
)
from securecode_ai.core.root_cause import RootCauseEvidenceRefs, RootCauseRecord
from securecode_ai.core.security_invariants import SecurityInvariant

from .local_durable_files import durable_delete, durable_write_new
from .local_patch_status_lock import (
    StatusFileLockBusy,
    StatusFileLockError,
    status_file_lock,
)

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SELECTOR: Final = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_MAX_MANIFEST_BYTES: Final = 1_048_576
_RETENTION_SECONDS: Final = 86_400
_RETENTION_POLICY_ID: Final = "local-suggestion-24h-v1"
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400
_MANIFEST_KEYS: Final = frozenset(
    {
        "schema_version",
        "selector",
        "patch_sha256",
        "patch_size_bytes",
        "expires_at_unix",
        "retention_policy_id",
        "finding",
        "root_cause",
        "invariant",
        "regression",
        "rationale",
        "author",
    }
)


class PatchArtifactError(ValueError):
    """Fixed, non-echoing suggestion-store failure."""

    def __init__(self, reason: str = "PATCH_ARTIFACT_INVALID") -> None:
        self.reason = reason
        super().__init__("patch suggestion artifact is unavailable")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class StoredPatchArtifact:
    selector: str
    patch_path: Path
    patch_bytes: bytes
    manifest_sha256: str
    expires_at_unix: int
    retention_policy_id: str
    architect_result: ArchitectPatchResult
    finding: FindingCase
    root_cause: RootCauseRecord
    invariant: SecurityInvariant
    regression: SecurityRegressionDescriptor
    author: ProducerRef


class PatchArtifactStore:
    """Exclusive-write content store rooted outside one inspected checkout."""

    def __init__(self, *, root: Path, checkout: Path, now: float | None = None) -> None:
        self._checkout = _absolute_directory(checkout, must_exist=True)
        self._root = _absolute_directory(root, must_exist=False)
        if _is_within(self._root, self._checkout):
            raise PatchArtifactError("ARTIFACT_ROOT_INSIDE_CHECKOUT")
        _mkdir_checked(self._root)
        if _is_within(self._root.resolve(), self._checkout.resolve()):
            raise PatchArtifactError("ARTIFACT_ROOT_INSIDE_CHECKOUT")
        self._now = int(time.time() if now is None else now)
        if self._now < 0:
            raise PatchArtifactError("ARTIFACT_CLOCK_INVALID")

    @property
    def root(self) -> Path:
        return self._root

    def put(
        self,
        *,
        patch_bytes: bytes,
        architect_result: ArchitectPatchResult,
        finding: FindingCase,
        root_cause: RootCauseRecord,
        invariant: SecurityInvariant,
        regression: SecurityRegressionDescriptor,
        author: ProducerRef,
    ) -> StoredPatchArtifact:
        if type(patch_bytes) is not bytes or not patch_bytes or len(patch_bytes) > 131_072:
            raise PatchArtifactError()
        digest = hashlib.sha256(patch_bytes).hexdigest()
        if (
            type(architect_result) is not ArchitectPatchResult
            or architect_result.patch_candidate.unified_diff_sha256 != digest
            or architect_result.patch_candidate.diff_ref.content_sha256 != digest
            or architect_result.patch_candidate.diff_ref.size_bytes != len(patch_bytes)
            or architect_result.patch_candidate.repository_revision != finding.repository_revision
        ):
            raise PatchArtifactError("PATCH_CONTRACT_MISMATCH")
        selector = f"sha256:{digest}"
        directory = self._root / digest[:2]
        _mkdir_checked(directory)
        patch_path = directory / f"{digest}.patch"
        manifest_path = directory / f"{digest}.json"
        if patch_path.exists() or manifest_path.exists():
            stored = self.load(selector)
            if (
                stored.patch_bytes != patch_bytes
                or stored.architect_result != architect_result
                or stored.finding != finding
                or stored.root_cause != root_cause
                or stored.invariant != invariant
                or stored.regression != regression
                or stored.author != author
            ):
                raise PatchArtifactError("PATCH_ARTIFACT_COLLISION")
            return stored
        expires_at_unix = ((self._now // _RETENTION_SECONDS) + 1) * _RETENTION_SECONDS
        manifest = {
            "schema_version": "1.0.0",
            "selector": selector,
            "patch_sha256": digest,
            "patch_size_bytes": len(patch_bytes),
            "expires_at_unix": expires_at_unix,
            "retention_policy_id": _RETENTION_POLICY_ID,
            "finding": finding.model_dump(mode="json"),
            "root_cause": _jsonable(root_cause),
            "invariant": _jsonable(invariant),
            "regression": _jsonable(regression),
            "rationale": _jsonable(architect_result.rationale),
            "author": author.model_dump(mode="json"),
        }
        manifest_bytes = _canonical(manifest)
        if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
            raise PatchArtifactError("PATCH_MANIFEST_TOO_LARGE")
        created_patch = _write_once(patch_path, patch_bytes)
        try:
            _write_once(manifest_path, manifest_bytes)
        except Exception:
            if created_patch:
                with suppress(OSError):
                    durable_delete(patch_path)
            raise
        return self.load(selector)

    def load(self, selector: str) -> StoredPatchArtifact:
        digest = selector_digest(selector)
        directory = self._root / digest[:2]
        _assert_store_directory(directory, self._root)
        patch_path = directory / f"{digest}.patch"
        manifest_path = directory / f"{digest}.json"
        _assert_regular_leaf(patch_path)
        _assert_regular_leaf(manifest_path)
        try:
            patch_bytes = patch_path.read_bytes()
            manifest_bytes = manifest_path.read_bytes()
        except OSError:
            raise PatchArtifactError("PATCH_ARTIFACT_NOT_FOUND") from None
        if (
            not patch_bytes
            or len(patch_bytes) > 131_072
            or hashlib.sha256(patch_bytes).hexdigest() != digest
            or not manifest_bytes
            or len(manifest_bytes) > _MAX_MANIFEST_BYTES
        ):
            raise PatchArtifactError()
        document = _closed_json(manifest_bytes)
        if set(document) != _MANIFEST_KEYS:
            raise PatchArtifactError()
        expires_at = document["expires_at_unix"]
        if type(expires_at) is int and expires_at <= self._now:
            self.delete(selector)
            raise PatchArtifactError("PATCH_ARTIFACT_EXPIRED")
        if (
            document["schema_version"] != "1.0.0"
            or document["selector"] != f"sha256:{digest}"
            or document["patch_sha256"] != digest
            or document["patch_size_bytes"] != len(patch_bytes)
            or type(document["expires_at_unix"]) is not int
            or document["retention_policy_id"] != _RETENTION_POLICY_ID
        ):
            raise PatchArtifactError()
        finding = FindingCase.model_validate(_mapping(document["finding"]))
        root_cause = _root_cause(_mapping(document["root_cause"]))
        invariant = _invariant(_mapping(document["invariant"]))
        regression = _regression(_mapping(document["regression"]))
        rationale = _rationale(_mapping(document["rationale"]))
        author = ProducerRef.model_validate(_mapping(document["author"]))
        try:
            unified_diff = patch_bytes.decode("utf-8", errors="strict")
            rebuilt = emit_patch_candidate(
                finding,
                root_cause,
                invariant,
                regression,
                unified_diff=unified_diff,
                rationale="content-addressed local suggestion",
                touched_symbols=rationale.touched_symbols,
                author=author,
            )
        except Exception:
            raise PatchArtifactError("PATCH_CONTRACT_MISMATCH") from None
        if rebuilt.rationale != rationale:
            raise PatchArtifactError("PATCH_CONTRACT_MISMATCH")
        return StoredPatchArtifact(
            selector=f"sha256:{digest}",
            patch_path=patch_path,
            patch_bytes=patch_bytes,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            expires_at_unix=document["expires_at_unix"],
            retention_policy_id=document["retention_policy_id"],
            architect_result=rebuilt,
            finding=finding,
            root_cause=root_cause,
            invariant=invariant,
            regression=regression,
            author=author,
        )

    def delete(self, selector: str) -> None:
        """Remove one source-bearing suggestion and its metadata."""

        digest = selector_digest(selector)
        directory = self._root / digest[:2]
        if not directory.exists() and not directory.is_symlink():
            return
        _assert_store_directory(directory, self._root)
        status_lock = directory / ".status.lock"
        try:
            with status_file_lock(status_lock):
                for path in (
                    directory / f"{digest}.patch",
                    directory / f"{digest}.json",
                    directory / f"{digest}.status.json",
                ):
                    durable_delete(path)
        except StatusFileLockBusy:
            raise PatchArtifactError("PATCH_STATUS_BUSY") from None
        except StatusFileLockError:
            raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None
        except PatchArtifactError:
            raise
        except OSError:
            raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None


def selector_digest(selector: str) -> str:
    if type(selector) is not str:
        raise PatchArtifactError("PATCH_SELECTOR_INVALID")
    match = _SELECTOR.fullmatch(selector)
    if match is None:
        raise PatchArtifactError("PATCH_SELECTOR_INVALID")
    return match.group(1)


def default_patch_artifact_root(environment: Mapping[str, str]) -> Path:
    selected = environment.get("SECURECODE_AI_ARTIFACT_ROOT")
    if selected:
        return Path(selected)
    if os.name == "nt":
        base = environment.get("LOCALAPPDATA")
        if not base:
            raise PatchArtifactError("ARTIFACT_ROOT_UNAVAILABLE")
        return Path(base) / "SecureCodeAI" / "suggestions"
    base = environment.get("XDG_DATA_HOME")
    if base:
        return Path(base) / "securecode-ai" / "suggestions"
    return Path.home() / ".local" / "share" / "securecode-ai" / "suggestions"


def _mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise PatchArtifactError()
    return dict(value)


def _root_cause(value: dict[str, Any]) -> RootCauseRecord:
    evidence = _mapping(value.pop("evidence", None))
    raw_command = value.pop("command_operation_evidence", None)
    if raw_command is None:
        command = ()
    elif type(raw_command) is list:
        command = tuple(CommandOperationEvidence.model_validate(item) for item in raw_command)
    else:
        raise PatchArtifactError()
    return RootCauseRecord(
        **value,
        evidence=RootCauseEvidenceRefs(**evidence),
        command_operation_evidence=command,
    )


def _invariant(value: dict[str, Any]) -> SecurityInvariant:
    value["required_evidence_ids"] = tuple(value.get("required_evidence_ids", ()))
    raw_command = value.get("command_operation_evidence", ())
    if type(raw_command) is list:
        value["command_operation_evidence"] = tuple(
            CommandOperationEvidence.model_validate(item) for item in raw_command
        )
    elif type(raw_command) is not tuple:
        raise PatchArtifactError()
    return SecurityInvariant(**value)


def _regression(value: dict[str, Any]) -> SecurityRegressionDescriptor:
    raw_cases = value.pop("cases", None)
    if type(raw_cases) is not list:
        raise PatchArtifactError()
    cases = tuple(
        RegressionCase(
            case_id=item["case_id"],
            kind=RegressionCaseKind(item["kind"]),
            input_sha256=item["input_sha256"],
            input_size_bytes=item["input_size_bytes"],
            oracle_sha256=item["oracle_sha256"],
        )
        for item in (_mapping(raw) for raw in raw_cases)
    )
    return SecurityRegressionDescriptor(**value, cases=cases)


def _rationale(value: dict[str, Any]) -> PatchRationaleReceipt:
    raw_symbols = value.pop("touched_symbols", None)
    if type(raw_symbols) is not list:
        raise PatchArtifactError()
    symbols = tuple(TouchedSymbol(**_mapping(item)) for item in raw_symbols)
    return PatchRationaleReceipt(**value, touched_symbols=symbols)


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        if isinstance(value, type):
            raise TypeError("dataclass type is not a serializable value")
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise PatchArtifactError() from None


def _closed_json(raw: bytes) -> dict[str, Any]:
    def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result or "\x00" in key:
                raise PatchArtifactError()
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed)
    except PatchArtifactError:
        raise
    except Exception:
        raise PatchArtifactError() from None
    return _mapping(value)


def _absolute_directory(path: Path, *, must_exist: bool) -> Path:
    if not isinstance(path, Path) or "\x00" in str(path):
        raise PatchArtifactError("ARTIFACT_ROOT_INVALID")
    absolute = path.absolute()
    if must_exist and (not absolute.is_dir() or _is_link(absolute)):
        raise PatchArtifactError("ARTIFACT_ROOT_INVALID")
    return absolute


def _mkdir_checked(path: Path) -> None:
    try:
        path.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
        if os.name != "nt":
            path.chmod(stat.S_IRWXU)
            if stat.S_IMODE(path.stat().st_mode) != stat.S_IRWXU:
                raise PatchArtifactError("ARTIFACT_ROOT_PERMISSIONS_INVALID")
        current = path
        while True:
            if _is_link(current) or not current.is_dir():
                raise PatchArtifactError("ARTIFACT_ROOT_INVALID")
            if current.parent == current:
                break
            current = current.parent
    except PatchArtifactError:
        raise
    except OSError:
        raise PatchArtifactError("ARTIFACT_ROOT_UNAVAILABLE") from None


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _assert_regular_leaf(path: Path) -> None:
    if _is_link(path) or not path.is_file():
        raise PatchArtifactError("PATCH_ARTIFACT_NOT_FOUND")


def _assert_store_directory(path: Path, root: Path) -> None:
    current = path
    while True:
        if _is_link(current) or not current.is_dir():
            raise PatchArtifactError("PATCH_ARTIFACT_NOT_FOUND")
        if current == root:
            break
        if current.parent == current:
            raise PatchArtifactError("PATCH_ARTIFACT_NOT_FOUND")
        current = current.parent
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        raise PatchArtifactError("PATCH_ARTIFACT_NOT_FOUND") from None


def _write_once(path: Path, content: bytes) -> bool:
    if path.exists():
        _assert_regular_leaf(path)
        try:
            if path.read_bytes() != content:
                raise PatchArtifactError("PATCH_ARTIFACT_COLLISION")
        except OSError:
            raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None
        return False
    try:
        durable_write_new(path, content)
        _assert_regular_leaf(path)
        return True
    except FileExistsError:
        return _write_once(path, content)
    except PatchArtifactError:
        raise
    except OSError:
        raise PatchArtifactError("PATCH_ARTIFACT_UNAVAILABLE") from None


__all__ = [
    "PatchArtifactError",
    "PatchArtifactStore",
    "StoredPatchArtifact",
    "default_patch_artifact_root",
    "selector_digest",
]
