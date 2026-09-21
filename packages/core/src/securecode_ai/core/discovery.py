"""Deterministic repository metadata discovery over an admitted inventory."""

from __future__ import annotations

from .discovery_changed import (
    ChangedFileEntry,
    ChangedFilesMap,
    ChangedFileStatus,
    build_changed_files_map,
)
from .discovery_changed import (
    _changed_map_hash_values as _changed_map_hash_values,
)
from .discovery_primitives import (
    _MAX_DISCOVERY_FILES as _MAX_DISCOVERY_FILES,
)
from .discovery_primitives import (
    DependencyEcosystem,
    DependencyManifestEntry,
    DependencyManifestKind,
    DiscoveredLanguageFile,
    DiscoveryError,
    DiscoveryErrorCode,
    DiscoveryManifest,
    IgnoredFile,
    IgnorePolicy,
    IgnoreRule,
    IgnoreRuleKind,
    LanguageId,
    LanguageManifestEntry,
    LanguageSupport,
)
from .discovery_primitives import (
    _canonical_hash as _canonical_hash,
)
from .discovery_primitives import (
    _discovery_payload as _discovery_payload,
)
from .discovery_repository import discover_repository

for _discovery_type in (
    DiscoveryError,
    IgnoreRule,
    IgnorePolicy,
    DiscoveredLanguageFile,
    LanguageManifestEntry,
    DependencyManifestEntry,
    IgnoredFile,
    DiscoveryManifest,
    ChangedFileEntry,
    ChangedFilesMap,
):
    _discovery_type.__module__ = __name__
del _discovery_type
__all__ = [
    "ChangedFileEntry",
    "ChangedFileStatus",
    "ChangedFilesMap",
    "DependencyEcosystem",
    "DependencyManifestEntry",
    "DependencyManifestKind",
    "DiscoveredLanguageFile",
    "DiscoveryError",
    "DiscoveryErrorCode",
    "DiscoveryManifest",
    "IgnorePolicy",
    "IgnoreRule",
    "IgnoreRuleKind",
    "IgnoredFile",
    "LanguageId",
    "LanguageManifestEntry",
    "LanguageSupport",
    "build_changed_files_map",
    "discover_repository",
]
