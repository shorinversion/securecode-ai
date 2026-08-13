"""Wire, version, classification and stable-ID tests for P1.6 AuditEvent."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TypedDict

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ActorRef,
    ActorType,
    ArtifactRef,
    AuditEvent,
    ContractExtension,
    DataClass,
    DiscoveryLane,
    EventSafePayload,
    EventType,
    ExtensionDataClass,
    ProducerRef,
    StableIdKind,
    derive_event_id,
    derive_idempotency_key,
    derive_stable_id,
)


class WireArguments(TypedDict):
    schema_version: str


class StableArguments(TypedDict):
    tenant_id: str
    scope_id: str
    semantic_sha256: str


WIRE: WireArguments = {"schema_version": CONTRACT_SCHEMA_VERSION}
NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
HEAD_SHA = "a" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64


def _event(
    *,
    sequence: int = 1,
    previous_event_hash: str | None = None,
    event_type: EventType = EventType.RUN_STARTED,
    data_class: DataClass | None = None,
    safe_payload: EventSafePayload | None = None,
    payload_ref: ArtifactRef | None = None,
    operation_hash: str = HASH_A,
    occurred_at: datetime = NOW,
    recorded_at: datetime = NOW + timedelta(seconds=1),
) -> AuditEvent:
    idempotency_key = derive_idempotency_key(
        tenant_id="tenant-1",
        run_id="run-1",
        operation_sha256=operation_hash,
    )
    if safe_payload is None and payload_ref is None:
        safe_payload = EventSafePayload(**WIRE, head_sha=HEAD_SHA)
    if data_class is None:
        data_class = (
            DataClass.CONFIDENTIAL_SECURITY
            if safe_payload is not None and safe_payload.carries_security_state
            else DataClass.INTERNAL_METADATA
        )
    return AuditEvent(
        **WIRE,
        event_id=derive_event_id(
            tenant_id="tenant-1",
            run_id="run-1",
            idempotency_key=idempotency_key,
        ),
        event_type=event_type,
        event_version="1.0.0",
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        tenant_id="tenant-1",
        run_id="run-1",
        sequence=sequence,
        previous_event_hash=previous_event_hash,
        actor=ActorRef(**WIRE, actor_id="worker-1", actor_type=ActorType.WORKER),
        correlation_id="correlation-1",
        causation_id=None if sequence == 1 else "cause-1",
        idempotency_key=idempotency_key,
        execution_identity_hash=HASH_B,
        data_class=data_class,
        safe_payload=safe_payload,
        payload_ref=payload_ref,
    )


def _artifact(
    *,
    tenant_id: str = "tenant-1",
    data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE,
) -> ArtifactRef:
    return ArtifactRef(
        **WIRE,
        tenant_id=tenant_id,
        content_id="source-artifact",
        content_sha256=HASH_A,
        size_bytes=42,
        data_class=data_class,
    )


def _extension(
    *,
    tenant_id: str,
    data_class: ExtensionDataClass = ExtensionDataClass.INTERNAL_METADATA,
) -> ContractExtension:
    return ContractExtension(
        namespace="vendor.event",
        extension_version="0.2.0",
        data_class=data_class,
        tenant_id=tenant_id,
        content_id="extension-metadata",
        payload_sha256=HASH_A,
        payload_size_bytes=1,
    )


def test_stable_id_golden_values_and_material_mutations() -> None:
    assert (
        derive_stable_id(
            StableIdKind.FINDING,
            tenant_id="tenant-1",
            scope_id="repo-1",
            semantic_sha256=HASH_A,
        )
        == "find:b13828a5feceff6d4723f0dafb6e04b83a4445179eda3b223bc94241ecc3b324"
    )
    key = derive_idempotency_key(tenant_id="tenant-1", run_id="run-1", operation_sha256=HASH_B)
    assert key == "idem:815c25a026b7aa246f261653f7711e40867572718dca914aee8456038c08ab56"
    assert (
        derive_event_id(tenant_id="tenant-1", run_id="run-1", idempotency_key=key)
        == "evt:c9dea3c7e178fa50813d8cfd61836a8bb5f4bced451983ffda34f1d589ea90bf"
    )
    baseline = derive_stable_id(
        StableIdKind.EVIDENCE,
        tenant_id="tenant-1",
        scope_id="run-1",
        semantic_sha256=HASH_A,
    )
    mutations = {
        derive_stable_id(
            StableIdKind.FINDING,
            tenant_id="tenant-1",
            scope_id="run-1",
            semantic_sha256=HASH_A,
        ),
        derive_stable_id(
            StableIdKind.EVIDENCE,
            tenant_id="tenant-2",
            scope_id="run-1",
            semantic_sha256=HASH_A,
        ),
        derive_stable_id(
            StableIdKind.EVIDENCE,
            tenant_id="tenant-1",
            scope_id="run-2",
            semantic_sha256=HASH_A,
        ),
        derive_stable_id(
            StableIdKind.EVIDENCE,
            tenant_id="tenant-1",
            scope_id="run-1",
            semantic_sha256=HASH_B,
        ),
    }
    assert baseline not in mutations
    assert len(mutations) == 4


@pytest.mark.parametrize(
    ("field", "value"),
    [("tenant_id", "../tenant"), ("scope_id", "bad scope"), ("semantic_sha256", "x")],
)
def test_stable_id_derivation_rejects_unvalidated_material(field: str, value: str) -> None:
    arguments: StableArguments = {
        "tenant_id": "tenant-1",
        "scope_id": "run-1",
        "semantic_sha256": HASH_A,
    }
    arguments[field] = value  # type: ignore[literal-required]
    with pytest.raises(ValidationError):
        derive_stable_id(StableIdKind.EVENT, **arguments)


def test_audit_event_round_trip_is_closed_immutable_and_hash_stable() -> None:
    event = _event()
    encoded = event.model_dump_json()
    assert AuditEvent.model_validate_json(encoded) == event
    assert event.canonical_hash() == AuditEvent.model_validate_json(encoded).canonical_hash()
    assert event.canonical_hash() == (
        "be25892d31f39d2344fdcb6cfa975533664d444dcbc1796afe251848070846e2"
    )
    with pytest.raises(ValidationError, match="Extra inputs"):
        AuditEvent.model_validate({**event.model_dump(mode="python"), "raw_log": "forbidden"})
    with pytest.raises(ValidationError, match="frozen"):
        event.sequence = 2


def test_event_order_uses_sequence_not_clock_values() -> None:
    skewed = _event(occurred_at=NOW + timedelta(days=1), recorded_at=NOW)
    assert skewed.sequence == 1
    assert skewed.occurred_at > skewed.recorded_at


@pytest.mark.parametrize(
    ("sequence", "previous"),
    [(1, HASH_A), (2, None)],
)
def test_genesis_and_successor_previous_hash_shape_is_closed(
    sequence: int, previous: str | None
) -> None:
    with pytest.raises(ValidationError, match="sequence one"):
        _event(sequence=sequence, previous_event_hash=previous)


def test_event_id_and_event_major_are_fail_closed() -> None:
    values = _event().model_dump(mode="python")
    values["event_id"] = "evt:forged"
    with pytest.raises(ValidationError, match="stable event identity"):
        AuditEvent.model_validate(values)
    values = _event().model_dump(mode="python")
    values["event_version"] = "2.0.0"
    with pytest.raises(ValidationError, match="event payload major"):
        AuditEvent.model_validate(values)


def test_event_requires_exactly_one_safe_or_referenced_payload() -> None:
    values = _event().model_dump(mode="python")
    values["safe_payload"] = None
    with pytest.raises(ValidationError, match="exactly one"):
        AuditEvent.model_validate(values)


def test_semantic_event_cannot_bypass_typed_contract_with_opaque_payload() -> None:
    with pytest.raises(ValidationError, match="inline typed safe payload"):
        _event(
            event_type=EventType.COVERAGE_UPDATED,
            data_class=DataClass.CONFIDENTIAL_SOURCE,
            safe_payload=None,
            payload_ref=_artifact(),
        )


def test_execution_derived_event_requires_exact_revision() -> None:
    payload = EventSafePayload(
        **WIRE,
        producer=ProducerRef(
            **WIRE,
            producer_id="scanner-1",
            producer_version="1.0.0",
            producer_sha256=HASH_A,
        ),
        lane=DiscoveryLane.DETERMINISTIC,
        input_hashes=(HASH_A,),
    )
    with pytest.raises(ValidationError, match="exact payload head_sha"):
        _event(event_type=EventType.DISCOVERY_STARTED, safe_payload=payload)
    values = _event().model_dump(mode="python")
    values["payload_ref"] = _artifact()
    with pytest.raises(ValidationError, match="exactly one"):
        AuditEvent.model_validate(values)


@pytest.mark.parametrize(
    "data_class",
    [DataClass.CONFIDENTIAL_SOURCE, DataClass.RESTRICTED],
)
def test_dc3_dc4_payloads_are_reference_only_and_tenant_bound(
    data_class: DataClass,
) -> None:
    with pytest.raises(ValidationError, match="must use ArtifactRef"):
        _event(data_class=data_class)
    referenced = _event(
        data_class=data_class,
        safe_payload=None,
        payload_ref=_artifact(data_class=data_class),
    )
    assert referenced.payload_ref == _artifact(data_class=data_class)
    with pytest.raises(ValidationError, match="event tenant"):
        _event(
            data_class=data_class,
            safe_payload=None,
            payload_ref=_artifact(tenant_id="tenant-2", data_class=data_class),
        )


def test_payload_reference_class_must_match_event_class() -> None:
    with pytest.raises(ValidationError, match="data classes must match"):
        _event(
            data_class=DataClass.RESTRICTED,
            safe_payload=None,
            payload_ref=_artifact(data_class=DataClass.CONFIDENTIAL_SOURCE),
        )


def test_event_extensions_are_bound_to_event_tenant_recursively() -> None:
    values = _event().model_dump(mode="python")
    values["extensions"] = (_extension(tenant_id="tenant-2"),)
    with pytest.raises(ValidationError, match="public-root tenant"):
        AuditEvent.model_validate(values)
    payload = EventSafePayload(
        **WIRE,
        extensions=(_extension(tenant_id="tenant-2"),),
        head_sha=HEAD_SHA,
    )
    with pytest.raises(ValidationError, match="public-root tenant"):
        _event(safe_payload=payload)


def test_event_class_cannot_downgrade_nested_extension_classification() -> None:
    payload = EventSafePayload(
        **WIRE,
        extensions=(
            _extension(
                tenant_id="tenant-1",
                data_class=ExtensionDataClass.CONFIDENTIAL_SECURITY,
            ),
        ),
    )
    with pytest.raises(ValidationError, match="must not downgrade"):
        _event(data_class=DataClass.INTERNAL_METADATA, safe_payload=payload)
    assert _event(data_class=DataClass.CONFIDENTIAL_SECURITY, safe_payload=payload)


def test_scm_publication_requires_safe_ids_and_both_heads() -> None:
    with pytest.raises(ValidationError, match="SCM publication"):
        _event(event_type=EventType.SCM_PUBLICATION_RECORDED)
    payload = EventSafePayload(
        **WIRE,
        requested_head_sha=HEAD_SHA,
        current_head_sha="b" * 40,
        platform_response_id="check-run-1",
    )
    assert (
        _event(
            event_type=EventType.SCM_PUBLICATION_RECORDED,
            safe_payload=payload,
        ).safe_payload
        == payload
    )


def test_scm_primitive_metadata_cannot_be_smuggled_through_other_events() -> None:
    payload = EventSafePayload(
        **WIRE,
        requested_head_sha=HEAD_SHA,
        current_head_sha="b" * 40,
        platform_response_id="check-run-1",
    )
    with pytest.raises(ValidationError, match="not permitted for event type RunStarted"):
        _event(event_type=EventType.RUN_STARTED, safe_payload=payload)
    with pytest.raises(ValidationError, match="input_hashes is not permitted"):
        _event(
            event_type=EventType.RUN_STARTED,
            safe_payload=EventSafePayload(**WIRE, input_hashes=(HASH_A,)),
        )


def test_dc3_dc4_artifact_event_uses_top_level_reference_only() -> None:
    payload = EventSafePayload(
        **WIRE,
        artifact_ref=_artifact(data_class=DataClass.RESTRICTED),
    )
    with pytest.raises(ValidationError, match="top-level payload_ref"):
        _event(
            event_type=EventType.ARTIFACT_RECORDED,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            safe_payload=payload,
        )


def test_audit_event_schema_has_no_raw_content_field_or_generic_status() -> None:
    document = AuditEvent.model_json_schema(mode="validation")
    encoded = json.dumps(document, sort_keys=True)
    forbidden = (
        '"raw_source"',
        '"prompt_text"',
        '"model_output"',
        '"raw_log"',
        '"command"',
        '"status"',
    )
    assert all(field not in encoded for field in forbidden)
    assert set(EventType) == {EventType(value) for value in EventType}
