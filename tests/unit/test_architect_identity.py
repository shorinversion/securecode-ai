"""Identity-boundary tests for Architect patch candidates."""

from __future__ import annotations

import dataclasses

import pytest
from securecode_ai.contracts import FindingCase, PatchStatus
from securecode_ai.core.architect import (
    ArchitectErrorCode,
    ArchitectPatchError,
    ArchitectPatchResult,
    TouchedSymbol,
    emit_patch_candidate,
)
from securecode_ai.core.regression import (
    RegressionCase,
    RegressionCaseKind,
    SecurityRegressionDescriptor,
    _descriptor_hash,
    build_security_regression_descriptor,
)
from securecode_ai.core.root_cause import (
    RootCauseEvidenceRefs,
    RootCauseRecord,
    _record_id,
    localize_root_cause,
)
from securecode_ai.core.security_invariants import (
    SecurityInvariant,
    _invariant_hash,
    build_security_invariant,
)

from tests.integration.test_cwe89_repair import _finding_graph, _producer

_HEAD = "b" * 40
_SOURCE_SHA256 = "a" * 64
_DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
_RATIONALE = "Cross-scope isolation probe."


def _reference() -> tuple[
    FindingCase,
    RootCauseRecord,
    SecurityInvariant,
    SecurityRegressionDescriptor,
]:
    finding, graph = _finding_graph(_SOURCE_SHA256, _HEAD)
    receipt = localize_root_cause(
        finding,
        graph,
        RootCauseEvidenceRefs(
            "evidence-source",
            "evidence-propagation",
            "evidence-sink",
        ),
    )
    assert receipt.record is not None
    root = receipt.record
    invariant = build_security_invariant(finding, root)
    descriptor = build_security_regression_descriptor(
        root,
        invariant,
        tuple(
            RegressionCase(
                f"case-{kind.value.lower()}",
                kind,
                "c" * 64,
                1,
                "d" * 64,
            )
            for kind in RegressionCaseKind
        ),
    )
    return finding, root, invariant, descriptor


def _emit(
    finding: FindingCase,
    root: RootCauseRecord,
    invariant: SecurityInvariant,
    descriptor: SecurityRegressionDescriptor,
) -> ArchitectPatchResult:
    return emit_patch_candidate(
        finding,
        root,
        invariant,
        descriptor,
        unified_diff=_DIFF,
        rationale=_RATIONALE,
        touched_symbols=(TouchedSymbol("app.py", "function", "get_user", 1, 1, _SOURCE_SHA256),),
        author=_producer(),
    )


def _replace_finding(finding: FindingCase, field: str, value: str) -> FindingCase:
    payload = finding.model_dump(mode="python")
    payload["repository_revision"][field] = value
    payload["evidence_graph_ref"]["tenant_id"] = payload["repository_revision"]["tenant_id"]
    return FindingCase.model_validate(payload)


def _replace_root(root: RootCauseRecord, field: str, value: str) -> RootCauseRecord:
    values = {item.name: getattr(root, item.name) for item in dataclasses.fields(root)}
    values[field] = value
    values["record_id"] = _record_id(
        finding_id=values["finding_id"],
        candidate_id=values["candidate_id"],
        candidate_version=values["candidate_version"],
        tenant_id=values["tenant_id"],
        repository_id=values["repository_id"],
        head_sha=values["head_sha"],
        root_cause_fingerprint=values["root_cause_fingerprint"],
        evidence_graph_id=values["evidence_graph_id"],
        evidence_graph_sha256=values["evidence_graph_sha256"],
        evidence=values["evidence"],
    )
    return RootCauseRecord(**values)


def _replace_invariant(invariant: SecurityInvariant, **changes: object) -> SecurityInvariant:
    values = {item.name: getattr(invariant, item.name) for item in dataclasses.fields(invariant)}
    values.update(changes)
    seed = object.__new__(SecurityInvariant)
    for name, value in values.items():
        object.__setattr__(seed, name, value)
    values["invariant_sha256"] = _invariant_hash(seed)
    return SecurityInvariant(**values)


def _replace_descriptor(
    descriptor: SecurityRegressionDescriptor, **changes: object
) -> SecurityRegressionDescriptor:
    values = {item.name: getattr(descriptor, item.name) for item in dataclasses.fields(descriptor)}
    values.update(changes)
    seed = object.__new__(SecurityRegressionDescriptor)
    for name, value in values.items():
        object.__setattr__(seed, name, value)
    values["descriptor_sha256"] = _descriptor_hash(seed)
    return SecurityRegressionDescriptor(**values)


def test_same_scope_reference_output_remains_suggested_and_identical() -> None:
    reference = _reference()

    first = _emit(*reference)
    second = _emit(*reference)

    assert first == second
    assert first.patch_candidate.patch_status is PatchStatus.SUGGESTED


@pytest.mark.parametrize("participant", ("finding", "root", "invariant", "regression"))
@pytest.mark.parametrize("field", ("tenant_id", "repository_id"))
def test_each_single_participant_cross_scope_mismatch_is_rejected(
    participant: str, field: str
) -> None:
    finding, root, invariant, descriptor = _reference()
    changed_value = f"other-{field}"
    if participant == "finding":
        finding = _replace_finding(finding, field, changed_value)
    elif participant == "root":
        root = _replace_root(root, field, changed_value)
    elif participant == "invariant":
        invariant = _replace_invariant(invariant, **{field: changed_value})
    else:
        descriptor = _replace_descriptor(descriptor, **{field: changed_value})

    with pytest.raises(ArchitectPatchError) as error:
        _emit(finding, root, invariant, descriptor)

    assert error.value.code is ArchitectErrorCode.IDENTITY_MISMATCH
    assert _RATIONALE not in str(error.value)


@pytest.mark.parametrize("field", ("tenant_id", "repository_id"))
def test_matching_root_invariant_and_regression_scope_cannot_diverge_from_finding(
    field: str,
) -> None:
    finding, root, invariant, descriptor = _reference()
    changed_value = f"other-{field}"
    root = _replace_root(root, field, changed_value)
    invariant = _replace_invariant(
        invariant,
        **{field: changed_value, "root_cause_id": root.record_id},
    )
    descriptor = _replace_descriptor(
        descriptor,
        **{
            field: changed_value,
            "root_cause_id": root.record_id,
            "invariant_sha256": invariant.invariant_sha256,
        },
    )

    with pytest.raises(ArchitectPatchError) as error:
        _emit(finding, root, invariant, descriptor)

    assert error.value.code is ArchitectErrorCode.IDENTITY_MISMATCH
