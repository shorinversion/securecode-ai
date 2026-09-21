"""Deterministic repository metadata discovery over an admitted inventory."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .discovery_primitives import (
    _MAX_DISCOVERY_FILES,
    _RULE_ID,
    _SHA256,
    DiscoveryError,
    DiscoveryErrorCode,
    DiscoveryManifest,
    _canonical_hash,
    _valid_relative_path,
)


class ChangedFileStatus(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNCHANGED = "unchanged"


@dataclass(frozen=True, slots=True)
class ChangedFileEntry:
    path: str
    status: ChangedFileStatus
    base_content_sha256: str | None
    head_content_sha256: str | None
    base_ignored_by_rule_id: str | None
    head_ignored_by_rule_id: str | None

    def __post_init__(self) -> None:
        if not _valid_relative_path(self.path) or type(self.status) is not ChangedFileStatus:
            raise ValueError("changed file entry is invalid")
        if any(
            value is not None and (type(value) is not str or not _SHA256.fullmatch(value))
            for value in (self.base_content_sha256, self.head_content_sha256)
        ):
            raise ValueError("changed file entry is invalid")
        if any(
            value is not None and (type(value) is not str or not _RULE_ID.fullmatch(value))
            for value in (self.base_ignored_by_rule_id, self.head_ignored_by_rule_id)
        ):
            raise ValueError("changed file entry is invalid")
        if (
            (self.base_content_sha256 is None) != (self.base_ignored_by_rule_id is None)
            and self.base_ignored_by_rule_id is not None
        ) or (
            (self.head_content_sha256 is None) != (self.head_ignored_by_rule_id is None)
            and self.head_ignored_by_rule_id is not None
        ):
            raise ValueError("changed file entry is invalid")
        expected = {
            (False, True): ChangedFileStatus.ADDED,
            (True, False): ChangedFileStatus.DELETED,
            (True, True): (
                ChangedFileStatus.UNCHANGED
                if self.base_content_sha256 == self.head_content_sha256
                else ChangedFileStatus.MODIFIED
            ),
        }.get((self.base_content_sha256 is not None, self.head_content_sha256 is not None))
        if self.status is not expected:
            raise ValueError("changed file entry is invalid")


@dataclass(frozen=True, slots=True)
class ChangedFilesMap:
    base_manifest: DiscoveryManifest
    head_manifest: DiscoveryManifest
    entries: tuple[ChangedFileEntry, ...]
    map_sha256: str

    @property
    def base_manifest_sha256(self) -> str:
        return self.base_manifest.manifest_sha256

    @property
    def head_manifest_sha256(self) -> str:
        return self.head_manifest.manifest_sha256

    @property
    def ignore_policy_sha256(self) -> str:
        return self.base_manifest.ignore_policy_sha256

    def __post_init__(self) -> None:
        if (
            type(self.base_manifest) is not DiscoveryManifest
            or type(self.head_manifest) is not DiscoveryManifest
            or type(self.map_sha256) is not str
            or not _SHA256.fullmatch(self.map_sha256)
            or type(self.entries) is not tuple
            or len(self.entries) > _MAX_DISCOVERY_FILES * 2
            or any(type(item) is not ChangedFileEntry for item in self.entries)
            or tuple(item.path for item in self.entries)
            != tuple(sorted(item.path for item in self.entries))
            or len({item.path for item in self.entries}) != len(self.entries)
            or self.base_manifest.ignore_policy != self.head_manifest.ignore_policy
            or self.entries
            != _derive_changed_entries(
                self.base_manifest,
                self.head_manifest,
            )
            or self.map_sha256 != _changed_map_hash(self)
        ):
            raise ValueError("changed files map is invalid")


def _changed_map_hash_values(
    base_manifest_sha256: str,
    head_manifest_sha256: str,
    ignore_policy_sha256: str,
    entries: tuple[ChangedFileEntry, ...],
) -> str:
    return _canonical_hash(
        {
            "base_manifest_sha256": base_manifest_sha256,
            "head_manifest_sha256": head_manifest_sha256,
            "ignore_policy_sha256": ignore_policy_sha256,
            "entries": [
                {
                    "path": item.path,
                    "status": item.status.value,
                    "base_sha256": item.base_content_sha256,
                    "head_sha256": item.head_content_sha256,
                    "base_ignored_by_rule_id": item.base_ignored_by_rule_id,
                    "head_ignored_by_rule_id": item.head_ignored_by_rule_id,
                }
                for item in entries
            ],
        }
    )


def _changed_map_hash(value: ChangedFilesMap) -> str:
    return _changed_map_hash_values(
        value.base_manifest_sha256,
        value.head_manifest_sha256,
        value.ignore_policy_sha256,
        value.entries,
    )


def build_changed_files_map(
    base: DiscoveryManifest,
    head: DiscoveryManifest,
) -> ChangedFilesMap:
    """Compare analyzed paths under one exact ignore policy without rename guesses."""

    if type(base) is not DiscoveryManifest or type(head) is not DiscoveryManifest:
        raise TypeError("discovery manifest is invalid")
    if base.ignore_policy_sha256 != head.ignore_policy_sha256:
        raise DiscoveryError(DiscoveryErrorCode.POLICY_MISMATCH)
    entries_tuple = _derive_changed_entries(base, head)
    map_hash = _changed_map_hash_values(
        base.manifest_sha256,
        head.manifest_sha256,
        base.ignore_policy_sha256,
        entries_tuple,
    )
    return ChangedFilesMap(
        base_manifest=base,
        head_manifest=head,
        entries=entries_tuple,
        map_sha256=map_hash,
    )


def _derive_changed_entries(
    base: DiscoveryManifest,
    head: DiscoveryManifest,
) -> tuple[ChangedFileEntry, ...]:
    base_files: dict[str, tuple[str, str | None]] = {
        item.path: (item.content_sha256, None) for item in base.analyzed_files
    }
    base_files.update(
        {item.path: (item.content_sha256, item.rule_id) for item in base.ignored_files}
    )
    head_files: dict[str, tuple[str, str | None]] = {
        item.path: (item.content_sha256, None) for item in head.analyzed_files
    }
    head_files.update(
        {item.path: (item.content_sha256, item.rule_id) for item in head.ignored_files}
    )
    entries: list[ChangedFileEntry] = []
    for path in sorted(base_files.keys() | head_files.keys()):
        base_value = base_files.get(path)
        head_value = head_files.get(path)
        base_hash = base_value[0] if base_value is not None else None
        head_hash = head_value[0] if head_value is not None else None
        base_rule = base_value[1] if base_value is not None else None
        head_rule = head_value[1] if head_value is not None else None
        if base_value is None:
            status = ChangedFileStatus.ADDED
        elif head_value is None:
            status = ChangedFileStatus.DELETED
        elif base_hash == head_hash:
            status = ChangedFileStatus.UNCHANGED
        else:
            status = ChangedFileStatus.MODIFIED
        entries.append(ChangedFileEntry(path, status, base_hash, head_hash, base_rule, head_rule))
    return tuple(entries)
