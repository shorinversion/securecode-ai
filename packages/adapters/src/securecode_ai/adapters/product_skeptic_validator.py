"""Strict Skeptic response validation bound to trusted evidence context."""

from __future__ import annotations

import json

from securecode_ai.contracts import (
    ComponentPin,
    FindingVerdict,
    ModelPurpose,
    ModelRequest,
    ModelRole,
)
from securecode_ai.core import PayloadValidation
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.skeptic import (
    AuditorSnapshot,
    SkepticObjection,
    SkepticObjectionKind,
    SkepticOutput,
)

from .model import HmacContentIdentifier
from .product_skeptic_context import _package_matches_snapshot
from .product_skeptic_contracts import (
    _ID,
    _MAX_EVIDENCE_IDS,
    _MAX_NOTE_CHARACTERS,
    _MAX_OBJECTIONS,
    _MAX_WIRE_BYTES,
    SKEPTIC_WIRE_PIN,
    _copy_package,
    _copy_snapshot,
    _failure,
    _validated_content,
)


class SkepticPayloadValidator:
    """Strict private Skeptic wire leaf bound to one snapshot and package."""

    __slots__ = ("_content_identifier", "_package", "_snapshot")

    def __init__(
        self,
        *,
        package: EvidencePackage,
        snapshot: AuditorSnapshot,
        content_identifier: HmacContentIdentifier,
        expected_tenant_id: str | None = None,
    ) -> None:
        if type(content_identifier) is not HmacContentIdentifier:
            raise ValueError("trusted Skeptic context is invalid")
        self._package = _copy_package(package)
        self._snapshot = _copy_snapshot(snapshot)
        if expected_tenant_id is not None and (
            type(expected_tenant_id) is not str or _ID.fullmatch(expected_tenant_id) is None
        ):
            raise ValueError("trusted Skeptic context is invalid")
        if not _package_matches_snapshot(
            self._package, self._snapshot, expected_tenant_id=expected_tenant_id
        ):
            raise ValueError("trusted Skeptic context is invalid")
        self._content_identifier = content_identifier

    @property
    def validator(self) -> ComponentPin:
        return SKEPTIC_WIRE_PIN

    def _request_is_bound(self, request: ModelRequest) -> bool:
        return (
            type(request) is ModelRequest
            and request.role is ModelRole.SKEPTIC
            and request.mode is ModelPurpose.SKEPTIC_REVIEW
            and request.tenant_id == self._package.tenant_id
            and request.head_sha == self._package.head_sha
            and request.evidence == self._package.model_evidence
            and request.output_schema == self.validator
        )

    def parse(self, payload: object, *, request: ModelRequest) -> SkepticOutput:
        if not self._request_is_bound(request):
            raise ValueError("Skeptic request is invalid")
        if type(payload) is not dict or set(payload) != {"finding_verdict", "objections"}:
            raise ValueError("Skeptic wire payload is invalid")
        try:
            encoded = json.dumps(
                payload, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
            ).encode()
            if len(encoded) > _MAX_WIRE_BYTES:
                raise ValueError
            verdict = FindingVerdict(payload["finding_verdict"])
            objections_value = payload["objections"]
            if (
                type(payload["finding_verdict"]) is not str
                or verdict is FindingVerdict.NOT_EVALUATED
                or type(objections_value) is not list
                or len(objections_value) > _MAX_OBJECTIONS
            ):
                raise ValueError
            objections: list[SkepticObjection] = []
            total_evidence_ids = 0
            selected_ids = {item.evidence_id for item in self._package.selected}
            for item in objections_value:
                # A short free-text note is accepted and dropped: only the objection
                # kind and its evidence IDs carry meaning.
                if type(item) is not dict or set(item) - {"note"} != {"kind", "evidence_ids"}:
                    raise ValueError
                if "note" in item and (
                    type(item["note"]) is not str or len(item["note"]) > _MAX_NOTE_CHARACTERS
                ):
                    raise ValueError
                evidence_ids = item["evidence_ids"]
                if (
                    type(item["kind"]) is not str
                    or type(evidence_ids) is not list
                    or len(evidence_ids) > _MAX_EVIDENCE_IDS
                    or any(type(value) is not str for value in evidence_ids)
                ):
                    raise ValueError
                objection = SkepticObjection(
                    kind=SkepticObjectionKind(item["kind"]), evidence_ids=tuple(evidence_ids)
                )
                if not set(objection.evidence_ids).issubset(selected_ids):
                    raise ValueError
                if objection in objections:
                    # Two objections that differ only in their dropped notes say the
                    # same thing; one is kept instead of rejecting the whole review.
                    continue
                total_evidence_ids += len(objection.evidence_ids)
                if total_evidence_ids > _MAX_EVIDENCE_IDS:
                    raise ValueError
                objections.append(objection)
            return SkepticOutput(finding_verdict=verdict, objections=tuple(objections))
        except (TypeError, ValueError):
            raise ValueError("Skeptic wire payload is invalid") from None

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
        if (
            type(request) is not ModelRequest
            or request.role is not ModelRole.SKEPTIC
            or request.mode is not ModelPurpose.SKEPTIC_REVIEW
            or request.tenant_id != self._package.tenant_id
            or request.head_sha != self._package.head_sha
            or request.evidence != self._package.model_evidence
        ):
            return _failure(self.validator, "REQUEST_ROLE_PURPOSE_MISMATCH")
        if request.output_schema != self.validator:
            return _failure(self.validator, "OUTPUT_SCHEMA_PIN_MISMATCH")
        try:
            self.parse(payload, request=request)
        except ValueError:
            return _failure(self.validator, "SCHEMA_INVALID")
        return _validated_content(
            payload=payload,
            request=request,
            pin=self.validator,
            identifier=self._content_identifier,
        )
