"""Actual catalogue children over admitted Git bytes.

This module is an in-progress execution boundary, not a complete audit or a
publication authority. Child results alone cannot authorize a product PASS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from securecode_ai.core import RepositoryFile
from securecode_ai.core.discovery import IgnorePolicy, LanguageId, discover_repository
from securecode_ai.core.evidence_graph import (
    EvidenceGraph,
)
from securecode_ai.core.repository import RepositoryInventory, repository_tree_sha256

from .dependency_scanning import (
    ApprovedOsvScanner,
)
from .git_snapshot import GitObjectReader
from .native_sources import build_native_source_catalogue
from .product_execution_stages import (
    ProductDeterministicExecution,
    ProductSecretStageResult,
    _program_graph_language_bindings,
    execute_dependency_stage,
    execute_secret_stage,
)
from .product_scanner import (
    ProductDeterministicScanResult,
    scan_product_sources,
)
from .secret_detection import SecretFingerprintKey


class _SecretStageExecutor(Protocol):
    def __call__(
        self,
        *,
        reader: GitObjectReader,
        head_sha: str,
        repository_id: str,
        fingerprint_key: SecretFingerprintKey,
    ) -> ProductSecretStageResult: ...


def execute_deterministic_children(
    *,
    reader: GitObjectReader,
    head_sha: str,
    tenant_id: str,
    repository_id: str,
    content_key: bytes,
    fingerprint_key: SecretFingerprintKey,
    scanner: ApprovedOsvScanner | None,
    secret_stage: _SecretStageExecutor = execute_secret_stage,
) -> ProductDeterministicExecution:
    """Execute inherited scan obligations selected from immutable discovery.

    Host-installed accepted catalogue semantics select Python parse/CWE89,
    any-language secrets and supported ecosystem dependency manifests. Portfolio scanning
    executes additionally, never substitutes for selected children. Failures
    retain successful facts for subsequent independent review.
    """
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head_sha,
        tenant_id=tenant_id,
        repository_id=repository_id,
        content_key=content_key,
    )
    files = tuple(
        RepositoryFile(f.path, len(f.content), f.content_sha256) for f in catalogue.snapshot.files
    )
    inventory = RepositoryInventory(
        files, sum(f.size_bytes for f in files), repository_tree_sha256(files)
    )
    discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
    has_python = any(entry.language is LanguageId.PYTHON for entry in discovery.languages)
    has_secret_scan_input = bool(catalogue.snapshot.files)
    has_manifest = bool(discovery.dependency_manifests)
    selected = tuple(
        stage
        for stage, applicable in (
            ("python_parse_symbols", has_python),
            ("secret_scan", has_secret_scan_input),
            ("dependency_scan", has_manifest),
            ("cwe89_scan", has_python),
        )
        if applicable
    )
    outputs: dict[str, tuple[str, ...]] = {}
    obstacles = []
    if has_python:
        outputs["python_parse_symbols"] = tuple(
            index.index_sha256
            for index in catalogue.indexes
            if index.path.endswith((".py", ".pyi"))
        )
    try:
        scan = scan_product_sources(
            catalogue,
            tenant_id=tenant_id,
            repository_id=repository_id,
        )
    except Exception:
        # Preserve the independent model-native lane when the deterministic
        # worker fails before returning a typed result.  An empty graph is an
        # explicit failed child, never a successful zero finding observation.
        scan = ProductDeterministicScanResult(
            graph=EvidenceGraph(
                graph_id="product-deterministic-unavailable",
                tenant_id=tenant_id,
                head_sha=head_sha,
                candidates=(),
                evidence=(),
                edges=(),
            ),
            receipts=(),
            is_complete=False,
            source_aliases=(),
            source_bindings=(),
            program_graph=None,
            repository_id=repository_id,
        )
    if not scan.is_complete:
        obstacles.append("PRODUCT_STATIC_EXECUTION_FAILED")
    secrets = None
    if has_secret_scan_input:
        try:
            secrets = secret_stage(
                reader=reader,
                head_sha=head_sha,
                repository_id=repository_id,
                fingerprint_key=fingerprint_key,
            )
            outputs["secret_scan"] = (
                secrets.output_sha256,
                *(
                    _program_graph_language_bindings(catalogue, scan.program_graph)
                    if scan.is_complete and scan.program_graph is not None
                    else ()
                ),
            )
        except Exception:
            obstacles.append("PRODUCT_SECRET_EXECUTION_FAILED")
    dependencies = None
    if has_manifest:
        try:
            dependencies = execute_dependency_stage(
                reader=reader, head_sha=head_sha, repository_id=repository_id, scanner=scanner
            )
            outputs["dependency_scan"] = (dependencies.output_sha256,)
        except Exception:
            obstacles.append("PRODUCT_DEPENDENCY_EXECUTION_FAILED")
    if has_python and scan.is_complete and scan.program_graph is not None:
        outputs["cwe89_scan"] = (
            scan.graph.graph_sha256,
            scan.program_graph.graph_sha256,
        )
    return ProductDeterministicExecution(
        catalogue,
        repository_id,
        inventory.tree_sha256,
        discovery.manifest_sha256,
        selected,
        tuple((stage, outputs[stage]) for stage in selected if stage in outputs),
        secrets,
        dependencies,
        scan,
        tuple(obstacles),
    )


@dataclass(frozen=True, slots=True)
class ProductChildFacts:
    """Retained metadata artifact bytes, without source or matched values."""

    graph: EvidenceGraph
    artifacts: tuple[tuple[str, bytes], ...] = field(repr=False)


def child_fact_graph(execution: ProductDeterministicExecution, *, tenant_id: str) -> EvidenceGraph:
    from .product_execution_facts import child_fact_catalogue

    return child_fact_catalogue(execution, tenant_id=tenant_id).graph
