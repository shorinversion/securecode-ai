"""Actual catalogue children over admitted Git bytes.

This module is an in-progress execution boundary, not a complete audit or a
publication authority. Child results alone cannot authorize a product PASS.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from securecode_ai.core import RepositoryFile
from securecode_ai.core.discovery import (
    IgnorePolicy,
    LanguageId,
    discover_repository,
)
from securecode_ai.core.repository import RepositoryInventory, repository_tree_sha256
from securecode_ai.core.scanning import ScannerIsolationMode, ScannerRunStatus

from .dependency_scanning import (
    ApprovedOsvScanner,
    DependencyScanError,
    DependencyScanResult,
    scan_dependency_advisories,
)
from .dependency_scanning_manifests import parse_dependency_manifest
from .dependency_scanning_precedence import (
    DependencyManifestBinding,
    dependency_manifest_plan,
)
from .git_snapshot import GitObjectReader, materialize_git_snapshot
from .native_sources import NativeSourceCatalogue
from .product_scanner import (
    ProductDeterministicScanResult,
    ProductScannerSourceBinding,
    first_party_scanner_producer,
    scanner_facts_match_receipts,
)
from .secret_detection import SecretFingerprintKey, SecretScanResult, scan_secrets


@dataclass(frozen=True, slots=True)
class ProductSecretStageResult:
    """Value-free actual scan outputs; never retains source or key bytes."""

    head_sha: str
    results: tuple[SecretScanResult, ...]
    output_sha256: str


def execute_secret_stage(
    *,
    reader: GitObjectReader,
    head_sha: str,
    repository_id: str,
    fingerprint_key: SecretFingerprintKey,
) -> ProductSecretStageResult:
    """Verify Git closure and actually scan every admitted file.

    Exceptions remain failures, not successful zero-candidate observations.
    Scanning all files covers credentials outside language-specific source files.
    The host-owned reader is subject to the snapshot adapter's bounded budgets.
    """
    snapshot = materialize_git_snapshot(reader, head_sha)
    results = tuple(
        scan_secrets(
            repository_id=repository_id,
            revision=snapshot.head_sha,
            file=RepositoryFile(file.path, len(file.content), file.content_sha256),
            source=file.content,
            fingerprint_key=fingerprint_key,
        )
        for file in snapshot.files
    )
    material = [
        "product-secret-stage-v1",
        repository_id,
        snapshot.head_sha,
        snapshot.tree_oid,
        [(result.path, result.content_sha256, result.scan_sha256) for result in results],
    ]
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()
    return ProductSecretStageResult(snapshot.head_sha, results, digest)


@dataclass(frozen=True, slots=True)
class ProductDependencyStageResult:
    """Actual advisory results bound to immutable discovery metadata."""

    head_sha: str
    inventory_sha256: str
    discovery_sha256: str
    results: tuple[DependencyScanResult, ...]
    manifest_bindings: tuple[DependencyManifestBinding, ...]
    output_sha256: str


def execute_dependency_stage(
    *,
    reader: GitObjectReader,
    head_sha: str,
    repository_id: str,
    scanner: ApprovedOsvScanner | None,
) -> ProductDependencyStageResult:
    """Discover supported manifests independently and execute their approved port.

    Unsupported selected formats and port failures cannot become empty results.
    No repository-provided ignore policy or scanner identity is consumed.
    """
    snapshot = materialize_git_snapshot(reader, head_sha)
    files = tuple(RepositoryFile(f.path, len(f.content), f.content_sha256) for f in snapshot.files)
    inventory = RepositoryInventory(
        files, sum(f.size_bytes for f in files), repository_tree_sha256(files)
    )
    discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
    selected = discovery.dependency_manifests
    if selected and scanner is None:
        raise ValueError("PRODUCT_DEPENDENCY_PORT_UNAVAILABLE")
    contents = {f.path: f for f in snapshot.files}
    metadata = {f.path: f for f in files}
    manifest_contents = {manifest.path: contents[manifest.path].content for manifest in selected}
    scanned, bindings = dependency_manifest_plan(selected, manifest_contents)
    results = []
    for manifest in scanned:
        assert scanner is not None
        try:
            parsed = parse_dependency_manifest(
                repository_id=repository_id,
                revision=snapshot.head_sha,
                manifest=manifest,
                file=metadata[manifest.path],
                source=contents[manifest.path].content,
            )
            result = scan_dependency_advisories(parsed, scanner)
        except DependencyScanError:
            raise ValueError("PRODUCT_DEPENDENCY_EXECUTION_FAILED") from None
        results.append(result)
    material = [
        "product-dependency-stage-v1",
        repository_id,
        snapshot.head_sha,
        discovery.manifest_sha256,
        [
            (
                item.manifest_path,
                item.manifest_sha256,
                item.authority_path,
                item.authority_sha256,
            )
            for item in bindings
        ],
        [r.scan_sha256 for r in results],
    ]
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()
    return ProductDependencyStageResult(
        snapshot.head_sha,
        inventory.tree_sha256,
        discovery.manifest_sha256,
        tuple(results),
        bindings,
        digest,
    )


@dataclass(frozen=True, slots=True)
class ProductDeterministicExecution:
    """Actual host-selected child execution; not an audit verdict."""

    catalogue: NativeSourceCatalogue
    repository_id: str
    inventory_sha256: str
    discovery_sha256: str
    selected_child_ids: tuple[str, ...]
    child_output_hashes: tuple[tuple[str, tuple[str, ...]], ...]
    secrets: ProductSecretStageResult | None
    dependencies: ProductDependencyStageResult | None
    scan: ProductDeterministicScanResult
    obstacles: tuple[str, ...]

    @property
    def is_complete(self) -> bool:
        try:
            if self.obstacles or not self.scan.is_complete:
                return False
            self.catalogue.repository_view()
            self.scan.repository_view(self.catalogue)
            producer = first_party_scanner_producer()
            expected_bindings = tuple(
                ProductScannerSourceBinding(
                    "static-" + hashlib.sha256(index.path.encode()).hexdigest(),
                    self.scan.graph.tenant_id,
                    index.repository_id,
                    index.revision,
                    index.path,
                    len(index.source),
                    index.content_sha256,
                    producer.producer_sha256,
                )
                for index in self.catalogue.indexes
            )
            if self.scan.source_bindings != expected_bindings or len(self.scan.receipts) != len(
                expected_bindings
            ):
                return False
            for binding, receipt in zip(expected_bindings, self.scan.receipts, strict=True):
                receipt.__post_init__()
                if (
                    receipt.request_id != binding.request_id
                    or receipt.scanner.producer != producer
                    or receipt.status is not ScannerRunStatus.SUCCEEDED
                    or receipt.isolation is not ScannerIsolationMode.APPROVED_ISOLATED_WORKER
                    or receipt.input_bytes != binding.size_bytes
                    or any(
                        signal.tenant_id != binding.tenant_id
                        or signal.head_sha != binding.head_sha
                        or signal.location.path != binding.path
                        or signal.location.content_sha256 != binding.content_sha256
                        for signal in receipt.signals
                    )
                ):
                    return False
            if not scanner_facts_match_receipts(self.catalogue, self.scan):
                return False
            snapshot = self.catalogue.snapshot
            files = tuple(
                RepositoryFile(f.path, len(f.content), f.content_sha256) for f in snapshot.files
            )
            inventory = RepositoryInventory(
                files, sum(f.size_bytes for f in files), repository_tree_sha256(files)
            )
            discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
            python = any(entry.language is LanguageId.PYTHON for entry in discovery.languages)
            manifests = discovery.dependency_manifests
            expected_ids = tuple(
                stage
                for stage, applicable in (
                    ("python_parse_symbols", python),
                    ("secret_scan", bool(discovery.languages)),
                    ("dependency_scan", bool(manifests)),
                    ("cwe89_scan", python),
                )
                if applicable
            )
            if (
                self.inventory_sha256 != inventory.tree_sha256
                or self.discovery_sha256 != discovery.manifest_sha256
                or self.selected_child_ids != expected_ids
            ):
                return False
            expected = {}
            if python:
                expected["python_parse_symbols"] = tuple(
                    index.index_sha256
                    for index in self.catalogue.indexes
                    if index.path.endswith((".py", ".pyi"))
                )
                expected["cwe89_scan"] = (self.scan.graph.graph_sha256,)
            if discovery.languages:
                secrets = self.secrets
                if (
                    secrets is None
                    or secrets.head_sha != snapshot.head_sha
                    or tuple(
                        (r.path, r.content_sha256, r.source_size_bytes, r.repository_id, r.revision)
                        for r in secrets.results
                    )
                    != tuple(
                        (
                            f.path,
                            f.content_sha256,
                            len(f.content),
                            self.repository_id,
                            snapshot.head_sha,
                        )
                        for f in snapshot.files
                    )
                ):
                    return False
                for secret_result in secrets.results:
                    secret_result.__post_init__()
                material = [
                    "product-secret-stage-v1",
                    self.repository_id,
                    snapshot.head_sha,
                    snapshot.tree_oid,
                    [(r.path, r.content_sha256, r.scan_sha256) for r in secrets.results],
                ]
                digest = hashlib.sha256(
                    json.dumps(material, separators=(",", ":")).encode()
                ).hexdigest()
                if secrets.output_sha256 != digest:
                    return False
                expected["secret_scan"] = (digest,)
            if manifests:
                dependencies = self.dependencies
                contents = {f.path: f.content for f in snapshot.files}
                manifest_contents = {
                    manifest.path: contents[manifest.path] for manifest in manifests
                }
                scanned, bindings = dependency_manifest_plan(manifests, manifest_contents)
                if (
                    dependencies is None
                    or dependencies.head_sha != snapshot.head_sha
                    or dependencies.inventory_sha256 != inventory.tree_sha256
                    or dependencies.discovery_sha256 != discovery.manifest_sha256
                    or dependencies.manifest_bindings != bindings
                    or len(dependencies.results) != len(scanned)
                ):
                    return False
                metadata = {f.path: f for f in files}
                for manifest, result in zip(scanned, dependencies.results, strict=True):
                    parsed = parse_dependency_manifest(
                        repository_id=self.repository_id,
                        revision=snapshot.head_sha,
                        manifest=manifest,
                        file=metadata[manifest.path],
                        source=contents[manifest.path],
                    )
                    if result.manifest_scan_sha256 != parsed.manifest_scan_sha256:
                        return False
                material = [
                    "product-dependency-stage-v1",
                    self.repository_id,
                    snapshot.head_sha,
                    discovery.manifest_sha256,
                    [
                        (
                            item.manifest_path,
                            item.manifest_sha256,
                            item.authority_path,
                            item.authority_sha256,
                        )
                        for item in bindings
                    ],
                    [r.scan_sha256 for r in dependencies.results],
                ]
                digest = hashlib.sha256(
                    json.dumps(material, separators=(",", ":")).encode()
                ).hexdigest()
                if dependencies.output_sha256 != digest:
                    return False
                expected["dependency_scan"] = (digest,)
            return self.child_output_hashes == tuple(
                (stage, expected[stage]) for stage in expected_ids
            ) and all(hashes for hashes in expected.values())
        except Exception:
            return False
