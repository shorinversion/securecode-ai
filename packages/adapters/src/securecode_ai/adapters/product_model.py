"""Strict, role-specific structured-output leaves for product model calls.

These validators retain no provider text.  They validate narrow wire envelopes
and bind their content to an opaque tenant-scoped identifier.  Product
composition remains responsible for deriving authoritative candidate identities
and fingerprints from the source evidence it actually read.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    DataClass,
    FindingVerdict,
    ModelPurpose,
    ModelRequest,
    ModelRole,
)
from securecode_ai.core import PayloadValidation
from securecode_ai.core.auditor import (
    AUDITOR_VERDICTS,
    AuditorContractError,
    AuditorVerdict,
    parse_auditor_verdict,
)
from securecode_ai.core.evidence_package import EvidenceContextRef, EvidencePackage
from securecode_ai.core.model_discovery import ModelNativeCandidateDraft

from .model import HmacContentIdentifier

_MAX_CANDIDATES: Final = 4_096
_MAX_EVIDENCE_IDS: Final = 4_096
_MAX_RATIONALE_BYTES: Final = 4_096
_OPAQUE_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_OPAQUE_ID: Final = re.compile(_OPAQUE_ID_PATTERN)
_DISCOVERY_SCHEMA: Final = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "version": "1.0.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "maxItems": _MAX_CANDIDATES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["rule_id", "root_evidence_id", "evidence_ids"],
                "properties": {
                    "rule_id": {"type": "string", "pattern": _OPAQUE_ID_PATTERN},
                    "root_evidence_id": {"type": "string", "pattern": _OPAQUE_ID_PATTERN},
                    "evidence_ids": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": _MAX_EVIDENCE_IDS,
                        "uniqueItems": True,
                        "items": {"type": "string", "pattern": _OPAQUE_ID_PATTERN},
                    },
                },
            },
        }
    },
    "x-total-evidence-ids-max": _MAX_EVIDENCE_IDS,
}
_AUDITOR_SCHEMA: Final = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "version": "1.0.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_verdict", "cited_evidence_ids", "rationale"],
    "properties": {
        "finding_verdict": {
            "type": "string",
            "enum": [verdict.value for verdict in FindingVerdict if verdict in AUDITOR_VERDICTS],
        },
        "cited_evidence_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": _MAX_EVIDENCE_IDS,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": _OPAQUE_ID_PATTERN},
        },
        "rationale": {"type": "string", "minLength": 1, "x-maxUtf8Bytes": _MAX_RATIONALE_BYTES},
    },
}


def _schema_bytes(schema: object) -> bytes:
    return json.dumps(
        schema,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _schema_pin(component_id: str, encoded: bytes) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=component_id,
        component_version="1.0.0",
        content_sha256=hashlib.sha256(encoded).hexdigest(),
    )


MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON: Final = _schema_bytes(_DISCOVERY_SCHEMA)
AUDITOR_WIRE_SCHEMA_JSON: Final = _schema_bytes(_AUDITOR_SCHEMA)
MODEL_NATIVE_DISCOVERY_WIRE_PIN: Final = _schema_pin(
    "product-model-native-discovery-wire", MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON
)
AUDITOR_WIRE_PIN: Final = _schema_pin("product-auditor-wire", AUDITOR_WIRE_SCHEMA_JSON)


class DiscoverySchemaRefusalCategory(StrEnum):
    """Closed, source-free classification of a rejected discovery envelope."""

    NOT_OBSERVED = "NOT_OBSERVED"
    TOP_LEVEL_SHAPE = "TOP_LEVEL_SHAPE"
    CANDIDATE_LIST_SHAPE = "CANDIDATE_LIST_SHAPE"
    CANDIDATE_LIMIT = "CANDIDATE_LIMIT"
    CANDIDATE_SHAPE = "CANDIDATE_SHAPE"
    EVIDENCE_SELECTION_SHAPE = "EVIDENCE_SELECTION_SHAPE"
    UNKNOWN_RULE = "UNKNOWN_RULE"
    UNKNOWN_EVIDENCE = "UNKNOWN_EVIDENCE"
    DUPLICATE_HYPOTHESIS = "DUPLICATE_HYPOTHESIS"
    EVIDENCE_TOTAL_LIMIT = "EVIDENCE_TOTAL_LIMIT"


@dataclass(frozen=True, slots=True)
class ModelNativeDiscoveryWireCandidate:
    """Provider-normalized selectors, never an authoritative Core candidate."""

    rule_id: str
    root_evidence_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _OPAQUE_ID.fullmatch(value) is None
                for value in (self.rule_id, self.root_evidence_id)
            )
            or type(self.evidence_ids) is not tuple
            or not self.evidence_ids
            or any(
                type(value) is not str or _OPAQUE_ID.fullmatch(value) is None
                for value in self.evidence_ids
            )
            or len(self.evidence_ids) > _MAX_EVIDENCE_IDS
            or len(self.evidence_ids) != len(set(self.evidence_ids))
            or self.root_evidence_id not in self.evidence_ids
        ):
            raise ValueError("discovery wire candidate is invalid")
        object.__setattr__(self, "evidence_ids", tuple(sorted(self.evidence_ids)))


def to_model_native_candidate_draft(
    wire_candidate: ModelNativeDiscoveryWireCandidate,
    *,
    candidate_id: str,
    candidate_version: int,
    source_id: str,
    root_cause_fingerprint: str,
) -> ModelNativeCandidateDraft:
    """Build the existing Core draft only from host-derived authoritative fields."""

    if type(wire_candidate) is not ModelNativeDiscoveryWireCandidate:
        raise TypeError("discovery wire candidate must be typed")
    return ModelNativeCandidateDraft(
        candidate_id=candidate_id,
        candidate_version=candidate_version,
        source_id=source_id,
        root_cause_fingerprint=root_cause_fingerprint,
        evidence_ids=wire_candidate.evidence_ids,
    )


def _validation_failure(pin: ComponentPin, code: str) -> PayloadValidation:
    return PayloadValidation(False, code, None, None, pin)


def _validated_content(
    *,
    payload: object,
    request: ModelRequest,
    pin: ComponentPin,
    identifier: HmacContentIdentifier,
) -> PayloadValidation:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        content_id = identifier.identify(tenant_id=request.tenant_id, payload=encoded)
    except (TypeError, ValueError):
        return _validation_failure(pin, "CONTENT_IDENTIFICATION_FAILED")
    return PayloadValidation(True, None, content_id, DataClass.CONFIDENTIAL_SECURITY, pin)


def _copy_evidence_package(package: EvidencePackage) -> EvidencePackage:
    """Deep-validate immutable evidence metadata before retaining an Auditor binding."""

    try:
        selected = tuple(
            EvidenceContextRef(
                evidence_id=item.evidence_id,
                content_id=item.content_id,
                data_class=item.data_class,
                evidence_sha256=item.evidence_sha256,
                producer_id=item.producer_id,
                producer_version=item.producer_version,
                producer_sha256=item.producer_sha256,
                context_bytes=item.context_bytes,
                estimated_tokens=item.estimated_tokens,
            )
            for item in package.selected
        )
        return EvidencePackage(
            candidate_id=package.candidate_id,
            candidate_version=package.candidate_version,
            tenant_id=package.tenant_id,
            head_sha=package.head_sha,
            graph_id=package.graph_id,
            graph_sha256=package.graph_sha256,
            selection_sha256=package.selection_sha256,
            selected=selected,
            omitted_evidence_ids=tuple(package.omitted_evidence_ids),
            total_context_bytes=package.total_context_bytes,
            total_input_tokens=package.total_input_tokens,
            truncated=package.truncated,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValueError("trusted auditor context is invalid") from None


class ModelNativeDiscoveryPayloadValidator:
    """Validate closed discovery selectors against host-pre-registered context."""

    __slots__ = (
        "_content_identifier",
        "_evidence_ids",
        "_expected_head_sha",
        "_expected_tenant_id",
        "_last_schema_refusal_category",
        "_rule_ids",
    )

    def __init__(
        self,
        *,
        content_identifier: HmacContentIdentifier,
        rule_ids: frozenset[str],
        evidence_ids: frozenset[str],
        expected_tenant_id: str,
        expected_head_sha: str,
    ) -> None:
        if (
            type(content_identifier) is not HmacContentIdentifier
            or type(expected_tenant_id) is not str
            or _OPAQUE_ID.fullmatch(expected_tenant_id) is None
            or type(expected_head_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", expected_head_sha) is None
            or type(rule_ids) is not frozenset
            or type(evidence_ids) is not frozenset
            or not rule_ids
            or not evidence_ids
            or any(
                type(value) is not str or _OPAQUE_ID.fullmatch(value) is None
                for value in rule_ids | evidence_ids
            )
        ):
            raise ValueError("trusted discovery context is invalid")
        self._content_identifier = content_identifier
        self._rule_ids = frozenset(rule_ids)
        self._evidence_ids = frozenset(evidence_ids)
        self._expected_tenant_id = expected_tenant_id
        self._expected_head_sha = expected_head_sha
        self._last_schema_refusal_category = DiscoverySchemaRefusalCategory.NOT_OBSERVED

    @property
    def validator(self) -> ComponentPin:
        return MODEL_NATIVE_DISCOVERY_WIRE_PIN

    @property
    def last_schema_refusal_category(self) -> DiscoverySchemaRefusalCategory:
        """Return only the current closed category, never the rejected payload."""

        return self._last_schema_refusal_category

    def parse(self, payload: object) -> tuple[ModelNativeDiscoveryWireCandidate, ...]:
        if type(payload) is not dict or set(payload) != {"candidates"}:
            raise ValueError("discovery wire payload is invalid")
        candidates = payload["candidates"]
        if type(candidates) is not list or len(candidates) > _MAX_CANDIDATES:
            raise ValueError("discovery wire payload is invalid")
        parsed: list[ModelNativeDiscoveryWireCandidate] = []
        hypotheses: set[tuple[str, str]] = set()
        total_evidence_ids = 0
        for value in candidates:
            if type(value) is not dict or set(value) != {
                "rule_id",
                "root_evidence_id",
                "evidence_ids",
            }:
                raise ValueError("discovery wire payload is invalid")
            evidence = value["evidence_ids"]
            if type(evidence) is not list:
                raise ValueError("discovery wire payload is invalid")
            # Models often list the supporting evidence but omit the root itself, or
            # repeat an ID. The root must still be host-registered evidence below.
            root = value["root_evidence_id"]
            evidence = list(dict.fromkeys(([root] if root not in evidence else []) + evidence))
            try:
                candidate = ModelNativeDiscoveryWireCandidate(
                    rule_id=value["rule_id"],
                    root_evidence_id=value["root_evidence_id"],
                    evidence_ids=tuple(evidence),
                )
            except (TypeError, ValueError):
                raise ValueError("discovery wire payload is invalid") from None
            if (
                candidate.rule_id not in self._rule_ids
                or not set(candidate.evidence_ids).issubset(self._evidence_ids)
                or (candidate.rule_id, candidate.root_evidence_id) in hypotheses
                or total_evidence_ids + len(candidate.evidence_ids) > _MAX_EVIDENCE_IDS
            ):
                raise ValueError("discovery wire payload is invalid")
            hypotheses.add((candidate.rule_id, candidate.root_evidence_id))
            total_evidence_ids += len(candidate.evidence_ids)
            parsed.append(candidate)
        return tuple(parsed)

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
        self._last_schema_refusal_category = DiscoverySchemaRefusalCategory.NOT_OBSERVED
        if (
            type(request) is not ModelRequest
            or request.role is not ModelRole.DISCOVERY
            or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or request.evidence
        ):
            return _validation_failure(self.validator, "REQUEST_ROLE_PURPOSE_MISMATCH")
        if (
            request.tenant_id != self._expected_tenant_id
            or request.head_sha != self._expected_head_sha
        ):
            return _validation_failure(self.validator, "REQUEST_CONTEXT_MISMATCH")
        if request.output_schema != self.validator:
            return _validation_failure(self.validator, "OUTPUT_SCHEMA_PIN_MISMATCH")
        try:
            self.parse(payload)
        except ValueError:
            self._last_schema_refusal_category = self._classify_schema_refusal(payload)
            return _validation_failure(self.validator, "SCHEMA_INVALID")
        return _validated_content(
            payload=payload,
            request=request,
            pin=self.validator,
            identifier=self._content_identifier,
        )

    def _classify_schema_refusal(self, payload: object) -> DiscoverySchemaRefusalCategory:
        """Classify only a post-JSON validator refusal without retaining its values."""

        if type(payload) is not dict or set(payload) != {"candidates"}:
            return DiscoverySchemaRefusalCategory.TOP_LEVEL_SHAPE
        candidates = payload["candidates"]
        if type(candidates) is not list:
            return DiscoverySchemaRefusalCategory.CANDIDATE_LIST_SHAPE
        if len(candidates) > _MAX_CANDIDATES:
            return DiscoverySchemaRefusalCategory.CANDIDATE_LIMIT
        hypotheses: set[tuple[str, str]] = set()
        total_evidence_ids = 0
        for value in candidates:
            if type(value) is not dict or set(value) != {
                "rule_id",
                "root_evidence_id",
                "evidence_ids",
            }:
                return DiscoverySchemaRefusalCategory.CANDIDATE_SHAPE
            rule_id = value["rule_id"]
            root_evidence_id = value["root_evidence_id"]
            evidence_ids = value["evidence_ids"]
            if (
                type(rule_id) is not str
                or _OPAQUE_ID.fullmatch(rule_id) is None
                or type(root_evidence_id) is not str
                or _OPAQUE_ID.fullmatch(root_evidence_id) is None
                or type(evidence_ids) is not list
                or not evidence_ids
                or len(evidence_ids) > _MAX_EVIDENCE_IDS
                or any(
                    type(evidence_id) is not str or _OPAQUE_ID.fullmatch(evidence_id) is None
                    for evidence_id in evidence_ids
                )
                or len(evidence_ids) != len(set(evidence_ids))
                or root_evidence_id not in evidence_ids
            ):
                return DiscoverySchemaRefusalCategory.EVIDENCE_SELECTION_SHAPE
            if rule_id not in self._rule_ids:
                return DiscoverySchemaRefusalCategory.UNKNOWN_RULE
            if not set(evidence_ids).issubset(self._evidence_ids):
                return DiscoverySchemaRefusalCategory.UNKNOWN_EVIDENCE
            hypothesis = (rule_id, root_evidence_id)
            if hypothesis in hypotheses:
                return DiscoverySchemaRefusalCategory.DUPLICATE_HYPOTHESIS
            total_evidence_ids += len(evidence_ids)
            if total_evidence_ids > _MAX_EVIDENCE_IDS:
                return DiscoverySchemaRefusalCategory.EVIDENCE_TOTAL_LIMIT
            hypotheses.add(hypothesis)
        return DiscoverySchemaRefusalCategory.NOT_OBSERVED


class AuditorPayloadValidator:
    """Validate an Auditor wire envelope against one trusted evidence package."""

    __slots__ = ("_content_identifier", "_package")

    def __init__(
        self, *, package: EvidencePackage, content_identifier: HmacContentIdentifier
    ) -> None:
        if (
            type(package) is not EvidencePackage
            or type(content_identifier) is not HmacContentIdentifier
        ):
            raise ValueError("trusted auditor context is invalid")
        self._package = _copy_evidence_package(package)
        self._content_identifier = content_identifier

    @property
    def validator(self) -> ComponentPin:
        return AUDITOR_WIRE_PIN

    def _request_is_bound(self, request: ModelRequest) -> bool:
        return (
            type(request) is ModelRequest
            and request.role is ModelRole.AUDITOR
            and request.mode is ModelPurpose.CANDIDATE_INVESTIGATION
            and request.tenant_id == self._package.tenant_id
            and request.head_sha == self._package.head_sha
            and request.evidence == self._package.model_evidence
            and request.output_schema == self.validator
        )

    def parse(self, payload: object, *, request: ModelRequest) -> AuditorVerdict:
        if not self._request_is_bound(request):
            raise ValueError("auditor request is invalid")
        if type(payload) is not dict or set(payload) != {
            "finding_verdict",
            "cited_evidence_ids",
            "rationale",
        }:
            raise ValueError("auditor wire payload is invalid")
        citations = payload["cited_evidence_ids"]
        rationale = payload["rationale"]
        if (
            type(payload["finding_verdict"]) is not str
            or type(citations) is not list
            or any(type(value) is not str for value in citations)
            or len(citations) > _MAX_EVIDENCE_IDS
            or type(rationale) is not str
            or not rationale
            or len(rationale.encode()) > _MAX_RATIONALE_BYTES
        ):
            raise ValueError("auditor wire payload is invalid")
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            verdict_id = self._content_identifier.identify(
                tenant_id=request.tenant_id,
                payload=encoded,
            )
            return parse_auditor_verdict(
                self._package,
                {
                    "verdict_id": verdict_id,
                    "finding_verdict": payload["finding_verdict"],
                    "cited_evidence_ids": citations,
                    "rationale_sha256": hashlib.sha256(rationale.encode()).hexdigest(),
                },
            )
        except (AuditorContractError, TypeError, ValueError):
            raise ValueError("auditor wire payload is invalid") from None

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
        if (
            type(request) is not ModelRequest
            or request.role is not ModelRole.AUDITOR
            or request.mode is not ModelPurpose.CANDIDATE_INVESTIGATION
            or request.tenant_id != self._package.tenant_id
            or request.head_sha != self._package.head_sha
            or request.evidence != self._package.model_evidence
        ):
            return _validation_failure(self.validator, "REQUEST_ROLE_PURPOSE_MISMATCH")
        if request.output_schema != self.validator:
            return _validation_failure(self.validator, "OUTPUT_SCHEMA_PIN_MISMATCH")
        try:
            self.parse(payload, request=request)
        except ValueError:
            return _validation_failure(self.validator, "SCHEMA_INVALID")
        return _validated_content(
            payload=payload,
            request=request,
            pin=self.validator,
            identifier=self._content_identifier,
        )


__all__ = [
    "AUDITOR_WIRE_PIN",
    "MODEL_NATIVE_DISCOVERY_WIRE_PIN",
    "AuditorPayloadValidator",
    "DiscoverySchemaRefusalCategory",
    "ModelNativeDiscoveryPayloadValidator",
    "ModelNativeDiscoveryWireCandidate",
    "to_model_native_candidate_draft",
]
