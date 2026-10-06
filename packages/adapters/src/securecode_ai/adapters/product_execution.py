"""Actual catalogue children over admitted Git bytes.

This module is an in-progress execution boundary, not a complete audit or a
publication authority. Child results alone cannot authorize a product PASS.
"""

from __future__ import annotations

from .dependency_scanning import ApprovedOsvScanner
from .git_snapshot import GitObjectReader
from .product_execution_facts import (
    RestrictedProductDiscoveryView,
    child_fact_catalogue,
    execution_fact_graph,
    masked_product_sources,
    model_facing_execution,
    restricted_product_source_paths,
)
from .product_execution_orchestration import (
    ProductChildFacts,
    child_fact_graph,
)
from .product_execution_orchestration import (
    execute_deterministic_children as _execute_deterministic_children,
)
from .product_execution_stages import (
    ProductDependencyStageResult,
    ProductDeterministicExecution,
    ProductSecretStageResult,
    execute_dependency_stage,
    execute_secret_stage,
)
from .secret_detection import SecretFingerprintKey


def execute_deterministic_children(
    *,
    reader: GitObjectReader,
    head_sha: str,
    tenant_id: str,
    repository_id: str,
    content_key: bytes,
    fingerprint_key: SecretFingerprintKey,
    scanner: ApprovedOsvScanner | None,
) -> ProductDeterministicExecution:
    """Run deterministic children through the facade-owned stage bindings."""

    return _execute_deterministic_children(
        reader=reader,
        head_sha=head_sha,
        tenant_id=tenant_id,
        repository_id=repository_id,
        content_key=content_key,
        fingerprint_key=fingerprint_key,
        scanner=scanner,
        secret_stage=execute_secret_stage,
    )


__all__ = [
    "ProductChildFacts",
    "ProductDependencyStageResult",
    "ProductDeterministicExecution",
    "ProductSecretStageResult",
    "RestrictedProductDiscoveryView",
    "child_fact_catalogue",
    "child_fact_graph",
    "execute_dependency_stage",
    "execute_deterministic_children",
    "execute_secret_stage",
    "execution_fact_graph",
    "masked_product_sources",
    "model_facing_execution",
    "restricted_product_source_paths",
]

for _product_execution_type in (
    ProductSecretStageResult,
    ProductDependencyStageResult,
    ProductDeterministicExecution,
    ProductChildFacts,
    RestrictedProductDiscoveryView,
):
    _product_execution_type.__module__ = __name__
del _product_execution_type
