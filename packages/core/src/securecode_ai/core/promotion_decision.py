"""Authority-issued governed promotion decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/promotion-decision/v2\x00"
_APPROVAL_DOMAIN: Final = b"securecode-ai/promotion-appsec-approval/v1\x00"
_AUTHORITY_DOMAIN: Final = b"securecode-ai/promotion-authority/v1\x00"


class PromotionDecisionError(ValueError):
    """Safe decision failure with no source, prompt, or protected-data bytes."""

    def __init__(self) -> None:
        super().__init__("Promotion decision was rejected")
        self.__cause__ = None
        self.__context__ = None


class PromotionAction(StrEnum):
    PROMOTE = "PROMOTE"
    NO_PROMOTION = "NO_PROMOTION"


@dataclass(frozen=True, slots=True)
class PromotionCandidate:
    candidate_id: str
    version: int
    content_sha256: str
    owner_id: str
    evaluator_id: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.candidate_id, self.owner_id, self.evaluator_id)
            )
            or type(self.version) is not int
            or self.version < 1
            or type(self.content_sha256) is not str
            or _HASH.fullmatch(self.content_sha256) is None
        ):
            raise PromotionDecisionError()


@dataclass(frozen=True, slots=True)
class PromotionEvidenceHashes:
    """Exact hashes for every receipt required by the promotion policy."""

    synthetic_admission_sha256: str
    release_benchmark_sha256: str
    ablation_sha256: str
    calibration_held_out_sha256: str
    offline_optimization_sha256: str
    rlm_experiment_sha256: str
    held_out_sha256: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or _HASH.fullmatch(value) is None
            for value in asdict(self).values()
        ):
            raise PromotionDecisionError()


@dataclass(frozen=True, slots=True)
class ParetoEvidence:
    candidate_content_sha256: str
    quality_score: float
    cost_microunits: int
    latency_ms: int
    security_regressions: int
    unsafe_patches: int
    protected_data_accesses: int
    complete: bool

    def __post_init__(self) -> None:
        if (
            type(self.candidate_content_sha256) is not str
            or _HASH.fullmatch(self.candidate_content_sha256) is None
            or type(self.quality_score) is not float
            or not 0.0 <= self.quality_score <= 1.0
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.cost_microunits,
                    self.latency_ms,
                    self.security_regressions,
                    self.unsafe_patches,
                    self.protected_data_accesses,
                )
            )
            or type(self.complete) is not bool
        ):
            raise PromotionDecisionError()


@dataclass(frozen=True, slots=True)
class IndependentAppSecApproval:
    """Authority-sealed approval bound to one candidate and evidence bundle."""

    reviewer_id: str
    approval_sha256: str
    candidate_id: str
    candidate_version: int
    candidate_content_sha256: str
    evidence_sha256: str
    authority_id: str
    authorization_sha256: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.reviewer_id, self.candidate_id, self.authority_id)
            )
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.approval_sha256,
                    self.candidate_content_sha256,
                    self.evidence_sha256,
                    self.authorization_sha256,
                )
            )
        ):
            raise PromotionDecisionError()


@dataclass(frozen=True, slots=True)
class PromotionDecisionRequest:
    action: PromotionAction
    reason_code: str
    candidate: PromotionCandidate
    evidence: PromotionEvidenceHashes
    pareto: ParetoEvidence
    appsec: IndependentAppSecApproval

    def __post_init__(self) -> None:
        if (
            type(self.action) is not PromotionAction
            or type(self.reason_code) is not str
            or _ID.fullmatch(self.reason_code) is None
            or type(self.candidate) is not PromotionCandidate
            or type(self.evidence) is not PromotionEvidenceHashes
            or type(self.pareto) is not ParetoEvidence
            or type(self.appsec) is not IndependentAppSecApproval
        ):
            raise PromotionDecisionError()


@dataclass(frozen=True, slots=True)
class PromotionDecisionReceipt:
    """Canonical decision sealed by its configured promotion authority."""

    action: PromotionAction
    reason_code: str
    request: PromotionDecisionRequest
    evidence_sha256: str
    canonical_sha256: str
    authority_id: str
    authorization_sha256: str
    target_alias: str
    expected_revision: int
    expected_decision_sha256: str | None
    transition_nonce: str
    source_disclosed: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.action) is not PromotionAction
            or type(self.reason_code) is not str
            or _ID.fullmatch(self.reason_code) is None
            or type(self.request) is not PromotionDecisionRequest
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.evidence_sha256,
                    self.canonical_sha256,
                    self.authorization_sha256,
                )
            )
            or type(self.authority_id) is not str
            or _ID.fullmatch(self.authority_id) is None
            or type(self.target_alias) is not str
            or _ID.fullmatch(self.target_alias) is None
            or type(self.expected_revision) is not int
            or self.expected_revision < 0
            or (
                self.expected_decision_sha256 is not None
                and (
                    type(self.expected_decision_sha256) is not str
                    or _HASH.fullmatch(self.expected_decision_sha256) is None
                )
            )
            or (self.expected_revision == 0) is not (self.expected_decision_sha256 is None)
            or type(self.transition_nonce) is not str
            or _ID.fullmatch(self.transition_nonce) is None
            or self.source_disclosed is not False
        ):
            raise PromotionDecisionError()

    @property
    def candidate_id(self) -> str:
        return self.request.candidate.candidate_id

    @property
    def candidate_version(self) -> int:
        return self.request.candidate.version

    @property
    def content_sha256(self) -> str:
        return self.request.candidate.content_sha256

    @property
    def appsec_approval_sha256(self) -> str:
        return self.request.appsec.approval_sha256


class PromotionDecisionAuthority:
    """HMAC authority for AppSec approvals and promotion decisions."""

    __slots__ = ("_authority_id", "_key", "_key_check")

    _authority_id: str
    _key: bytes
    _key_check: bytes

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("PromotionDecisionAuthority is immutable")
        object.__setattr__(self, name, value)

    @classmethod
    def create(cls, *, authority_id: str, key: bytes) -> PromotionDecisionAuthority:
        if (
            type(authority_id) is not str
            or _ID.fullmatch(authority_id) is None
            or type(key) is not bytes
            or len(key) != 32
            or key == b"\x00" * 32
        ):
            raise PromotionDecisionError()
        value = cls.__new__(cls)
        object.__setattr__(value, "_authority_id", authority_id)
        object.__setattr__(value, "_key", bytes(key))
        object.__setattr__(value, "_key_check", hashlib.sha256(key).digest())
        return value

    def approve_appsec(
        self,
        *,
        reviewer_id: str,
        approval_sha256: str,
        candidate: PromotionCandidate,
        evidence: PromotionEvidenceHashes,
    ) -> IndependentAppSecApproval:
        if (
            type(candidate) is not PromotionCandidate
            or type(evidence) is not PromotionEvidenceHashes
        ):
            raise PromotionDecisionError()
        candidate, evidence = replace(candidate), replace(evidence)
        if (
            not self._intact()
            or type(reviewer_id) is not str
            or _ID.fullmatch(reviewer_id) is None
            or reviewer_id in {candidate.owner_id, candidate.evaluator_id}
            or type(approval_sha256) is not str
            or _HASH.fullmatch(approval_sha256) is None
        ):
            raise PromotionDecisionError()
        evidence_sha256 = _evidence_hash(evidence)
        material = _approval_material(
            reviewer_id,
            approval_sha256,
            candidate,
            evidence_sha256,
            self._authority_id,
        )
        return IndependentAppSecApproval(
            reviewer_id,
            approval_sha256,
            candidate.candidate_id,
            candidate.version,
            candidate.content_sha256,
            evidence_sha256,
            self._authority_id,
            self._sign(_APPROVAL_DOMAIN, material),
        )

    def decide(
        self,
        request: PromotionDecisionRequest,
        *,
        target_alias: str,
        expected_revision: int,
        expected_decision_sha256: str | None,
        transition_nonce: str,
    ) -> PromotionDecisionReceipt:
        checked = _copy_request(request)
        if not _transition_valid(
            target_alias, expected_revision, expected_decision_sha256, transition_nonce
        ) or not self._approval_valid(checked):
            raise PromotionDecisionError()
        action, reason = _effective_decision(checked)
        evidence_sha256 = _evidence_hash(checked.evidence)
        material = _decision_material(
            action,
            reason,
            checked,
            evidence_sha256,
            self._authority_id,
            target_alias,
            expected_revision,
            expected_decision_sha256,
            transition_nonce,
        )
        canonical_sha256 = _hash(material)
        return PromotionDecisionReceipt(
            action,
            reason,
            checked,
            evidence_sha256,
            canonical_sha256,
            self._authority_id,
            self._sign(_AUTHORITY_DOMAIN, material),
            target_alias,
            expected_revision,
            expected_decision_sha256,
            transition_nonce,
        )

    def verify(self, receipt: object) -> bool:
        return self.verify_and_snapshot(receipt) is not None

    def verify_and_snapshot(self, receipt: object) -> PromotionDecisionReceipt | None:
        try:
            if not self._intact() or type(receipt) is not PromotionDecisionReceipt:
                return None
            snapshot = deepcopy(receipt)
            checked = _copy_request(snapshot.request)
            snapshot = replace(snapshot, request=checked)
            if not _transition_valid(
                snapshot.target_alias,
                snapshot.expected_revision,
                snapshot.expected_decision_sha256,
                snapshot.transition_nonce,
            ):
                return None
            action, reason = _effective_decision(checked)
            evidence_sha256 = _evidence_hash(checked.evidence)
            material = _decision_material(
                action,
                reason,
                checked,
                evidence_sha256,
                self._authority_id,
                snapshot.target_alias,
                snapshot.expected_revision,
                snapshot.expected_decision_sha256,
                snapshot.transition_nonce,
            )
            if not (
                self._approval_valid(checked)
                and snapshot.action is action
                and snapshot.reason_code == reason
                and snapshot.evidence_sha256 == evidence_sha256
                and snapshot.authority_id == self._authority_id
                and snapshot.source_disclosed is False
                and snapshot.canonical_sha256 == _hash(material)
                and hmac.compare_digest(
                    snapshot.authorization_sha256, self._sign(_AUTHORITY_DOMAIN, material)
                )
            ):
                return None
            return snapshot
        except (AttributeError, TypeError, ValueError):
            return None

    def _approval_valid(self, request: PromotionDecisionRequest) -> bool:
        approval = request.appsec
        evidence_sha256 = _evidence_hash(request.evidence)
        material = _approval_material(
            approval.reviewer_id,
            approval.approval_sha256,
            request.candidate,
            evidence_sha256,
            self._authority_id,
        )
        return (
            approval.reviewer_id
            not in {
                request.candidate.owner_id,
                request.candidate.evaluator_id,
            }
            and approval.candidate_id == request.candidate.candidate_id
            and approval.candidate_version == request.candidate.version
            and approval.candidate_content_sha256 == request.candidate.content_sha256
            and approval.evidence_sha256 == evidence_sha256
            and approval.authority_id == self._authority_id
            and hmac.compare_digest(
                approval.authorization_sha256,
                self._sign(_APPROVAL_DOMAIN, material),
            )
        )

    def _sign(self, domain: bytes, material: object) -> str:
        if not self._intact():
            raise PromotionDecisionError()
        return hmac.new(self._key, domain + _json_bytes(material), hashlib.sha256).hexdigest()

    def _intact(self) -> bool:
        try:
            return (
                type(self) is PromotionDecisionAuthority
                and type(self._authority_id) is str
                and _ID.fullmatch(self._authority_id) is not None
                and type(self._key) is bytes
                and len(self._key) == 32
                and self._key != b"\x00" * 32
                and hmac.compare_digest(hashlib.sha256(self._key).digest(), self._key_check)
            )
        except Exception:
            return False


def decide_promotion(
    request: PromotionDecisionRequest,
    *,
    authority: PromotionDecisionAuthority,
    target_alias: str,
    expected_revision: int,
    expected_decision_sha256: str | None,
    transition_nonce: str,
) -> PromotionDecisionReceipt:
    """Issue a decision only through the explicitly configured authority."""

    if type(authority) is not PromotionDecisionAuthority:
        raise PromotionDecisionError()
    return authority.decide(
        request,
        target_alias=target_alias,
        expected_revision=expected_revision,
        expected_decision_sha256=expected_decision_sha256,
        transition_nonce=transition_nonce,
    )


def canonical_decision_json(receipt: PromotionDecisionReceipt) -> str:
    if type(receipt) is not PromotionDecisionReceipt:
        raise PromotionDecisionError()
    names = (  # noqa: SIM905 - compact allowlist keeps this security module bounded
        "authority_id authorization_sha256 canonical_sha256 evidence_sha256 "
        "expected_decision_sha256 expected_revision reason_code source_disclosed "
        "target_alias transition_nonce"
    ).split()
    data = {name: getattr(receipt, name) for name in names}
    data.update(
        action=receipt.action.value,
        appsec_approval_sha256=receipt.appsec_approval_sha256,
        candidate_id=receipt.candidate_id,
        candidate_version=receipt.candidate_version,
        content_sha256=receipt.content_sha256,
    )
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"


def _effective_decision(request: PromotionDecisionRequest) -> tuple[PromotionAction, str]:
    if request.action is PromotionAction.PROMOTE and not _promotion_safe(request):
        return PromotionAction.NO_PROMOTION, "MISSING_OR_UNSAFE_EVIDENCE"
    return request.action, request.reason_code


def _promotion_safe(request: PromotionDecisionRequest) -> bool:
    candidate = request.candidate
    pareto = request.pareto
    approval = request.appsec
    return (
        pareto.complete
        and pareto.candidate_content_sha256 == candidate.content_sha256
        and pareto.security_regressions == 0
        and pareto.unsafe_patches == 0
        and pareto.protected_data_accesses == 0
        and approval.candidate_id == candidate.candidate_id
        and approval.candidate_version == candidate.version
        and approval.candidate_content_sha256 == candidate.content_sha256
        and approval.evidence_sha256 == _evidence_hash(request.evidence)
        and approval.reviewer_id not in {candidate.owner_id, candidate.evaluator_id}
        and candidate.owner_id != candidate.evaluator_id
    )


def _decision_material(
    action: PromotionAction,
    reason: str,
    request: PromotionDecisionRequest,
    evidence_sha256: str,
    authority_id: str,
    target_alias: str,
    expected_revision: int,
    expected_decision_sha256: str | None,
    transition_nonce: str,
) -> dict[str, object]:
    return {
        "action": action.value,
        "appsec": asdict(request.appsec),
        "authority_id": authority_id,
        "candidate": asdict(request.candidate),
        "evidence": asdict(request.evidence),
        "evidence_sha256": evidence_sha256,
        "expected_decision_sha256": expected_decision_sha256,
        "expected_revision": expected_revision,
        "pareto": asdict(request.pareto),
        "reason": reason,
        "requested_action": request.action.value,
        "requested_reason": request.reason_code,
        "target_alias": target_alias,
        "transition_nonce": transition_nonce,
    }


def _approval_material(
    reviewer_id: str,
    approval_sha256: str,
    candidate: PromotionCandidate,
    evidence_sha256: str,
    authority_id: str,
) -> dict[str, object]:
    return {
        "approval_sha256": approval_sha256,
        "authority_id": authority_id,
        "candidate": asdict(candidate),
        "evidence_sha256": evidence_sha256,
        "reviewer_id": reviewer_id,
    }


def _copy_request(value: PromotionDecisionRequest) -> PromotionDecisionRequest:
    if type(value) is not PromotionDecisionRequest:
        raise PromotionDecisionError()
    return replace(
        value,
        candidate=replace(value.candidate),
        evidence=replace(value.evidence),
        pareto=replace(value.pareto),
        appsec=replace(value.appsec),
    )


def _transition_valid(
    target_alias: object,
    expected_revision: object,
    expected_decision_sha256: object,
    transition_nonce: object,
) -> bool:
    return (
        type(target_alias) is str
        and _ID.fullmatch(target_alias) is not None
        and type(expected_revision) is int
        and expected_revision >= 0
        and (expected_revision == 0) is (expected_decision_sha256 is None)
        and (
            expected_decision_sha256 is None
            or (
                type(expected_decision_sha256) is str
                and _HASH.fullmatch(expected_decision_sha256) is not None
            )
        )
        and type(transition_nonce) is str
        and _ID.fullmatch(transition_nonce) is not None
    )


def _evidence_hash(value: PromotionEvidenceHashes) -> str:
    return _hash(asdict(value))


def _hash(value: object) -> str:
    return hashlib.sha256(_HASH_DOMAIN + _json_bytes(value)).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
