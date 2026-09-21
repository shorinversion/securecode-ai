"""Deterministic repository metadata discovery over an admitted inventory."""

from __future__ import annotations

from .discovery_primitives import (
    _MAX_DISCOVERY_FILES,
    DependencyManifestEntry,
    DiscoveredLanguageFile,
    DiscoveryError,
    DiscoveryErrorCode,
    DiscoveryManifest,
    IgnoredFile,
    IgnorePolicy,
    LanguageId,
    LanguageManifestEntry,
    LanguageSupport,
    _canonical_hash,
    _dependency_for,
    _discovery_payload,
    _language_for,
)
from .repository import RepositoryFile, RepositoryInventory


def discover_repository(
    inventory: RepositoryInventory,
    policy: IgnorePolicy,
) -> DiscoveryManifest:
    """Classify admitted metadata without reading or executing repository bytes."""

    if type(inventory) is not RepositoryInventory:
        raise TypeError("repository inventory is invalid")
    if type(policy) is not IgnorePolicy:
        raise TypeError("ignore policy is invalid")
    if len(inventory.files) > _MAX_DISCOVERY_FILES:
        raise DiscoveryError(DiscoveryErrorCode.INVENTORY_LIMIT)

    analyzed: list[RepositoryFile] = []
    ignored: list[IgnoredFile] = []
    language_files: dict[LanguageId, list[DiscoveredLanguageFile]] = {}
    dependencies: list[DependencyManifestEntry] = []
    for item in inventory.files:
        rule = policy.matching_rule(item.path)
        rule_id = rule.rule_id if rule is not None else None
        if rule_id is None:
            analyzed.append(item)
        else:
            ignored.append(IgnoredFile(item.path, item.size_bytes, item.content_sha256, rule_id))

        language = _language_for(item.path)
        if language is not None:
            language_files.setdefault(language, []).append(
                DiscoveredLanguageFile(item.path, item.content_sha256, rule_id)
            )
        dependency = _dependency_for(item.path)
        if dependency is not None:
            ecosystem, kind = dependency
            dependencies.append(
                DependencyManifestEntry(
                    item.path,
                    item.content_sha256,
                    ecosystem,
                    kind,
                    rule_id,
                )
            )

    languages = tuple(
        LanguageManifestEntry(
            language=language,
            support=(
                LanguageSupport.SUPPORTED
                if language is LanguageId.PYTHON
                else LanguageSupport.UNSUPPORTED
            ),
            files=tuple(files),
        )
        for language, files in sorted(language_files.items(), key=lambda pair: pair[0].value)
    )
    analyzed_tuple = tuple(analyzed)
    ignored_tuple = tuple(ignored)
    dependency_tuple = tuple(dependencies)
    manifest_hash = _canonical_hash(
        _discovery_payload(
            inventory.tree_sha256,
            policy,
            analyzed_tuple,
            ignored_tuple,
            languages,
            dependency_tuple,
        )
    )
    return DiscoveryManifest(
        inventory_tree_sha256=inventory.tree_sha256,
        ignore_policy=policy,
        analyzed_files=analyzed_tuple,
        ignored_files=ignored_tuple,
        languages=languages,
        dependency_manifests=dependency_tuple,
        manifest_sha256=manifest_hash,
    )
