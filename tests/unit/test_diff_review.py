"""P4.8 semantic diff review contracts; execution is deferred to G4 closure."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    ComponentPin,
    DataClass,
    PatchCandidate,
    PatchStatus,
    ProducerRef,
    RepositoryRevision,
    ResourceUsage,
    ValidationGateOutcome,
    ValidationGateResult,
    ValidationOutcome,
    ValidationResult,
)
from securecode_ai.core.architect import ArchitectPatchResult, TouchedSymbol, _make_rationale
from securecode_ai.core.diff_review import (
    BlastRadius,
    DiffReviewDisposition,
    DiffReviewError,
    DiffReviewErrorCode,
    SemanticRiskArea,
    review_semantic_diff,
)

HEAD = "a" * 40
FIXED_HEAD = "b" * 40
HASH = "c" * 64


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="diff-review",
        producer_version="1.0.0",
        producer_sha256=HASH,
    )


def _architect(symbols: tuple[TouchedSymbol, ...] | None = None) -> ArchitectPatchResult:
    diff_hash = hashlib.sha256(b"bounded-diff").hexdigest()
    patch = PatchCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        patch_id=f"patch-{diff_hash}",
        finding_id="finding-1",
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="git",
            repository_id="repo-1",
            head_sha=HEAD,
        ),
        unified_diff_sha256=diff_hash,
        diff_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            content_id=f"patch-{diff_hash}",
            content_sha256=diff_hash,
            size_bytes=12,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
        ),
        author=_producer(),
        patch_status=PatchStatus.SUGGESTED,
    )
    rationale = _make_rationale(
        finding_id="finding-1",
        root_cause_id="root-cause-1",
        invariant_id="CWE-89-PARAMETER-BINDING",
        invariant_version="1.0.0",
        regression_descriptor_id="regression-1",
        touched_symbols=symbols or (TouchedSymbol("app.py", "function", "get_user", 1, 8, HASH),),
    )
    return ArchitectPatchResult(patch, rationale)


def _validation(
    architect: ArchitectPatchResult,
    *,
    outcome: ValidationOutcome = ValidationOutcome.VALIDATED,
    head: str = FIXED_HEAD,
) -> ValidationResult:
    gate = ValidationGateResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        ordinal=1,
        gate_id="diff-parse",
        gate_outcome=ValidationGateOutcome.PASSED,
        producer=_producer(),
        input_hashes=(HASH,),
        output_hashes=(HASH,),
        resource_usage=ResourceUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            elapsed_ms=1,
            peak_memory_bytes=1,
            cpu_time_ms=1,
        ),
    )
    return ValidationResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        validation_id="validation-1",
        tenant_id="tenant-1",
        patch_id=architect.patch_candidate.patch_id,
        head_sha=head,
        sandbox_profile=_pin(),
        gates=(gate,),
        validation_outcome=outcome,
        result_sha256=HASH,
    )


def _pin() -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id="airgap-sandbox",
        component_version="1.0.0",
        content_sha256=HASH,
    )


def test_localized_parameterized_sql_review_is_not_an_approval() -> None:
    architect = _architect()
    receipt = review_semantic_diff(architect, _validation(architect))

    assert receipt.disposition is DiffReviewDisposition.REVIEWED_NO_HUMAN_MARKER
    assert receipt.blast_radius is BlastRadius.LOCALIZED
    assert receipt.risk_areas == (SemanticRiskArea.OTHER,)
    assert not receipt.human_required
    assert not receipt.approval_eligible


@pytest.mark.parametrize(
    ("name", "area"),
    [
        ("authenticate_user", SemanticRiskArea.AUTHENTICATION),
        ("authorize_user", SemanticRiskArea.AUTHORIZATION),
        ("public_api_handler", SemanticRiskArea.PUBLIC_API),
        ("encrypt_value", SemanticRiskArea.CRYPTOGRAPHY),
    ],
)
def test_sensitive_semantic_changes_always_require_human_review(
    name: str, area: SemanticRiskArea
) -> None:
    architect = _architect((TouchedSymbol("app.py", "function", name, 1, 8, HASH),))
    receipt = review_semantic_diff(architect, _validation(architect))

    assert receipt.disposition is DiffReviewDisposition.HUMAN_REQUIRED
    assert receipt.human_required
    assert area in receipt.risk_areas
    assert not receipt.approval_eligible


def test_unknown_or_cross_module_surface_requires_human_review() -> None:
    unknown = _architect((TouchedSymbol("app.py", "unknown", "get_user", 1, 8, HASH),))
    unknown_receipt = review_semantic_diff(unknown, _validation(unknown))
    assert unknown_receipt.disposition is DiffReviewDisposition.HUMAN_REQUIRED
    assert SemanticRiskArea.UNKNOWN in unknown_receipt.risk_areas

    cross = _architect(
        (
            TouchedSymbol("app.py", "function", "get_user", 1, 8, HASH),
            TouchedSymbol("db.py", "function", "parameterize", 1, 8, "d" * 64),
        )
    )
    cross_receipt = review_semantic_diff(cross, _validation(cross))
    assert cross_receipt.disposition is DiffReviewDisposition.HUMAN_REQUIRED
    assert cross_receipt.blast_radius is BlastRadius.CROSS_MODULE


def test_protected_symbol_paths_are_rejected() -> None:
    path = "specs/policy.yaml"
    architect = _architect((TouchedSymbol(path, "function", "get_user", 1, 8, HASH),))
    receipt = review_semantic_diff(architect, _validation(architect))

    assert receipt.disposition is DiffReviewDisposition.REJECTED
    assert not receipt.approval_eligible


def test_failed_validation_is_indeterminate_and_never_positive() -> None:
    architect = _architect()
    receipt = review_semantic_diff(
        architect, _validation(architect, outcome=ValidationOutcome.FAILED)
    )

    assert receipt.disposition is DiffReviewDisposition.INDETERMINATE
    assert not receipt.human_required
    assert not receipt.approval_eligible


@pytest.mark.parametrize("mutation", ["patch", "tenant", "head", "diff-ref"])
def test_patch_validation_identity_drift_is_rejected_before_classification(mutation: str) -> None:
    architect = _architect()
    validation = _validation(architect)
    if mutation == "patch":
        validation = validation.model_copy(update={"patch_id": "patch-other"})
    elif mutation == "tenant":
        validation = validation.model_copy(update={"tenant_id": "tenant-other"})
    elif mutation == "head":
        validation = validation.model_copy(update={"head_sha": HEAD})
    else:
        diff_ref = architect.patch_candidate.diff_ref.model_copy(
            update={"content_id": "other-patch"}
        )
        candidate = architect.patch_candidate.model_copy(update={"diff_ref": diff_ref})
        architect = ArchitectPatchResult(candidate, architect.rationale)
        validation = _validation(architect)

    with pytest.raises(DiffReviewError) as error:
        review_semantic_diff(architect, validation)
    assert error.value.code is DiffReviewErrorCode.INTEGRITY_FAILURE


def test_tampered_rationale_and_marker_do_not_echo_source_data() -> None:
    marker = "SOURCE_SECRET_CANARY"
    architect = _architect((TouchedSymbol("app.py", "function", marker, 1, 8, HASH),))
    receipt = review_semantic_diff(architect, _validation(architect))
    assert marker not in str(receipt)

    object.__setattr__(architect.rationale, "rationale_sha256", "0" * 64)
    with pytest.raises(DiffReviewError) as error:
        review_semantic_diff(architect, _validation(architect))
    assert marker not in str(error.value)
