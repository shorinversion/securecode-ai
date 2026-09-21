"""Isolated, replay-safe Evaluation Lab orchestration and promotion policy."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, replace
from threading import RLock
from typing import Final

from .evaluation_access import (
    EvaluationAccessAuthority,
    EvaluationAccessGrant,
    EvaluationCapability,
    EvaluationRole,
    require_access,
)
from .evaluation_authority import (
    FIXED_MAX_CASES,
    FIXED_MAX_ELAPSED_MS,
    FIXED_MAX_TOKENS,
    EvaluationEvidenceAuthority,
    EvaluationExecutionReceipt,
    EvaluationObservedExecution,
    EvaluationSecurityReceipt,
)
from .evaluation_candidate_store import EvaluationCandidateStore
from .evaluation_lab_evidence import (
    AuthoritativePromotionEvidence,
    evaluation_envelope_hash,
    evaluation_execution_isolated,
    evaluation_run_id,
    execution_matches_run,
    launch_evidence_hash,
    snapshot_candidate,
    with_launch_evidence,
    with_run_evidence,
)
from .evaluation_lab_models import (
    EvaluationBudget,
    EvaluationDatasetRef,
    EvaluationLabError,
    EvaluationLabErrorCode,
    EvaluationLaunchDisposition,
    EvaluationLaunchReceipt,
    EvaluationLaunchRequest,
    EvaluationPartition,
    EvaluationPinSet,
    EvaluationPromotionDisposition,
    EvaluationPromotionReceipt,
    EvaluationPromotionRequest,
    EvaluationRunDisposition,
    EvaluationRunReceipt,
    EvaluationSandboxEnvelope,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class _LaunchedRun:
    receipt: EvaluationLaunchReceipt
    evidence_sha256: str


@dataclass(frozen=True, slots=True)
class _RecordedRun:
    receipt: EvaluationRunReceipt
    execution: EvaluationExecutionReceipt


class EvaluationLab:
    __slots__ = (
        "_access_authority",
        "_candidate_store",
        "_datasets",
        "_evidence_authority",
        "_launches",
        "_lock",
        "_promotions",
        "_results",
    )

    def __init__(
        self,
        candidate_store: EvaluationCandidateStore,
        evidence_authority: EvaluationEvidenceAuthority,
        access_authority: EvaluationAccessAuthority,
    ) -> None:
        if (
            type(candidate_store) is not EvaluationCandidateStore
            or type(evidence_authority) is not EvaluationEvidenceAuthority
            or type(access_authority) is not EvaluationAccessAuthority
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
        self._candidate_store = candidate_store
        self._access_authority = access_authority
        self._evidence_authority = evidence_authority
        self._datasets: dict[str, EvaluationDatasetRef] = {}
        self._launches: dict[str, _LaunchedRun] = {}
        self._results: dict[str, _RecordedRun] = {}
        self._promotions: dict[str, EvaluationPromotionReceipt] = {}
        self._lock = RLock()

    def launch(self, request: EvaluationLaunchRequest) -> EvaluationLaunchReceipt:
        if type(request) is not EvaluationLaunchRequest:
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
        request = EvaluationLaunchRequest(
            request.role,
            request.actor_id,
            request.candidate_key,
            EvaluationDatasetRef(
                request.dataset.dataset_id,
                request.dataset.partition,
                request.dataset.dataset_sha256,
                request.dataset.lineage_sha256,
                tuple(request.dataset.case_ids),
            ),
            EvaluationPinSet(
                request.pins.profile_sha256,
                request.pins.prompt_sha256,
                request.pins.tool_sha256,
                request.pins.model_sha256,
                request.pins.policy_sha256,
            ),
            request.access_grant,
        )
        run_id = evaluation_run_id(request)
        try:
            verified_grant = require_access(
                self._access_authority,
                request.access_grant,
                capability=_capability_for(request.dataset.partition),
                actor_id=request.actor_id,
                candidate_key=request.candidate_key,
                dataset_id=request.dataset.dataset_id,
                dataset_sha256=request.dataset.dataset_sha256,
                run_id=run_id,
            )
            candidate = snapshot_candidate(self._candidate_store.resolve(request.candidate_key))
        except Exception:
            raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED) from None
        if verified_grant.role is not request.role:
            raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED)
        self._register_dataset(request.dataset)
        envelope = EvaluationSandboxEnvelope(True, True, True, True, False, EvaluationBudget())
        receipt = EvaluationLaunchReceipt(
            EvaluationLaunchDisposition.CREATED,
            run_id,
            candidate,
            request.dataset.dataset_sha256,
            request.dataset.partition,
            request.pins,
            envelope,
            "0" * 64,
        )
        receipt = with_launch_evidence(receipt)
        with self._lock:
            existing = self._launches.get(run_id)
            if existing is None:
                self._launches[run_id] = _LaunchedRun(
                    deepcopy(receipt), receipt.launch_evidence_sha256
                )
                return deepcopy(receipt)
            if existing.receipt == receipt:
                return replace(
                    deepcopy(existing.receipt), disposition=EvaluationLaunchDisposition.IDEMPOTENT
                )
        raise EvaluationLabError(EvaluationLabErrorCode.REPLAY_CONFLICT)

    def issue_execution(
        self,
        *,
        actor_id: str,
        access_grant: EvaluationAccessGrant,
        observation: EvaluationObservedExecution,
    ) -> EvaluationExecutionReceipt:
        with self._lock:
            launch = self._launches.get(observation.run_id)
            if launch is None:
                raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
            dataset = self._datasets.get(launch.receipt.dataset_sha256)
            if dataset is None:
                dataset = next(
                    (
                        value
                        for value in self._datasets.values()
                        if value.dataset_sha256 == launch.receipt.dataset_sha256
                    ),
                    None,
                )
            if dataset is None:
                raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
            try:
                return self._evidence_authority.issue_execution(
                    observation,
                    access_authority=self._access_authority,
                    access_grant=access_grant,
                    actor_id=actor_id,
                    capability=_capability_for(launch.receipt.partition),
                    candidate_key=launch.receipt.candidate.candidate_key,
                    dataset_id=dataset.dataset_id,
                    dataset_sha256=dataset.dataset_sha256,
                    expected_run_id=launch.receipt.run_id,
                    expected_launch_evidence_sha256=launch.evidence_sha256,
                    expected_envelope_sha256=evaluation_envelope_hash(launch.receipt.envelope),
                    expected_case_ids=dataset.case_ids,
                )
            except Exception:
                raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED) from None

    def record_execution(
        self,
        *,
        role: EvaluationRole,
        actor_id: str,
        access_grant: EvaluationAccessGrant,
        result: EvaluationExecutionReceipt,
    ) -> EvaluationRunReceipt:
        if (
            type(role) is not EvaluationRole
            or type(actor_id) is not str
            or type(access_grant) is not EvaluationAccessGrant
            or type(result) is not EvaluationExecutionReceipt
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
        verified = self._evidence_authority.verify_and_copy_execution(result)
        if verified is None:
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
        with self._lock:
            launch = self._launches.get(verified.run_id)
            if launch is None:
                raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
            try:
                dataset = next(
                    value
                    for value in self._datasets.values()
                    if value.dataset_sha256 == launch.receipt.dataset_sha256
                )
                grant = require_access(
                    self._access_authority,
                    access_grant,
                    capability=_capability_for(launch.receipt.partition),
                    actor_id=actor_id,
                    candidate_key=launch.receipt.candidate.candidate_key,
                    dataset_id=dataset.dataset_id,
                    dataset_sha256=dataset.dataset_sha256,
                    run_id=launch.receipt.run_id,
                )
            except Exception:
                raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED) from None
            if (
                grant.role is not role
                or verified.actor_id != actor_id
                or verified.access_grant_sha256 != grant.grant_sha256
                or launch_evidence_hash(launch.receipt) != launch.evidence_sha256
                or verified.launch_evidence_sha256 != launch.evidence_sha256
                or verified.envelope_sha256 != evaluation_envelope_hash(launch.receipt.envelope)
                or verified.network_accessed
                or verified.credentials_accessed
                or verified.source_disclosed
                or verified.locked_expectations_accessed
                or verified.observed_cases > FIXED_MAX_CASES
                or verified.observed_case_ids != dataset.case_ids
                or verified.observed_tokens > FIXED_MAX_TOKENS
                or verified.observed_elapsed_ms > FIXED_MAX_ELAPSED_MS
            ):
                raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
            receipt = EvaluationRunReceipt(
                EvaluationRunDisposition.RECORDED,
                verified.run_id,
                launch.receipt.candidate.candidate_key,
                launch.receipt.partition,
                verified.passed_cases,
                verified.failed_cases,
                verified.error_cases,
                verified.observed_cases,
                verified.observed_tokens,
                verified.observed_elapsed_ms,
                verified.result_sha256,
                verified.observed_case_ids,
                verified.execution_receipt_sha256,
                "0" * 64,
            )
            receipt = with_run_evidence(receipt, launch)
            existing = self._results.get(verified.run_id)
            if existing is None:
                self._results[verified.run_id] = _RecordedRun(deepcopy(receipt), deepcopy(verified))
                return deepcopy(receipt)
            if existing.receipt == receipt and existing.execution == verified:
                return replace(
                    deepcopy(existing.receipt), disposition=EvaluationRunDisposition.IDEMPOTENT
                )
        raise EvaluationLabError(EvaluationLabErrorCode.REPLAY_CONFLICT)

    def issue_security_approval(
        self,
        *,
        reviewer_id: str,
        candidate_key: str,
        held_out_run_id: str,
        approved: bool,
        access_grant: EvaluationAccessGrant,
    ) -> EvaluationSecurityReceipt:
        with self._lock:
            recorded = self._results.get(held_out_run_id)
            launch = self._launches.get(held_out_run_id)
            try:
                candidate = snapshot_candidate(self._candidate_store.resolve(candidate_key))
            except Exception:
                raise EvaluationLabError(EvaluationLabErrorCode.PROMOTION_DENIED) from None
            if (
                recorded is None
                or launch is None
                or recorded.receipt.candidate_key != candidate.candidate_key
                or reviewer_id == candidate.submitted_by
                or reviewer_id == recorded.execution.actor_id
            ):
                raise EvaluationLabError(EvaluationLabErrorCode.PROMOTION_DENIED)
            try:
                return self._evidence_authority.issue_security_approval(
                    reviewer_id=reviewer_id,
                    run_id=held_out_run_id,
                    candidate_key=candidate_key,
                    candidate_content_sha256=candidate.content_sha256,
                    run_evidence_sha256=recorded.receipt.run_evidence_sha256,
                    approved=approved,
                    access_authority=self._access_authority,
                    access_grant=access_grant,
                    authoritative_execution=recorded.execution,
                )
            except Exception:
                raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED) from None

    def promote(self, request: EvaluationPromotionRequest) -> EvaluationPromotionReceipt:
        if type(request) is not EvaluationPromotionRequest:
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)
        try:
            grant = require_access(
                self._access_authority,
                request.access_grant,
                capability=EvaluationCapability.PROMOTE,
                actor_id=request.actor_id,
                candidate_key=request.candidate_key,
                dataset_id=None,
                dataset_sha256=None,
                run_id=request.held_out_run_id,
            )
        except Exception:
            raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED) from None
        if grant.role is not request.role or request.actor_id != request.reviewer_id:
            raise EvaluationLabError(EvaluationLabErrorCode.ACCESS_DENIED)
        held_out = self.require_authoritative_promotion_evidence(
            candidate_key=request.candidate_key,
            held_out_run_id=request.held_out_run_id,
            reviewer_id=request.reviewer_id,
            security_receipt=request.security_receipt,
        )
        with self._lock:
            receipt = EvaluationPromotionReceipt(
                EvaluationPromotionDisposition.PROMOTED,
                request.candidate_key,
                held_out.run_id,
                request.reviewer_id,
                held_out.security_receipt_sha256,
            )
            existing = self._promotions.get(request.candidate_key)
            if existing is None:
                self._promotions[request.candidate_key] = receipt
                return receipt
            if existing == receipt:
                return EvaluationPromotionReceipt(
                    EvaluationPromotionDisposition.IDEMPOTENT,
                    existing.candidate_key,
                    existing.held_out_run_id,
                    existing.reviewer_id,
                    existing.security_receipt_sha256,
                )
        raise EvaluationLabError(EvaluationLabErrorCode.REPLAY_CONFLICT)

    def require_authoritative_promotion_evidence(
        self,
        *,
        candidate_key: str,
        held_out_run_id: str,
        reviewer_id: str,
        security_receipt: EvaluationSecurityReceipt,
    ) -> AuthoritativePromotionEvidence:
        if (
            type(candidate_key) is not str
            or _ID.fullmatch(candidate_key) is None
            or type(held_out_run_id) is not str
            or _ID.fullmatch(held_out_run_id) is None
            or type(reviewer_id) is not str
            or _ID.fullmatch(reviewer_id) is None
            or type(security_receipt) is not EvaluationSecurityReceipt
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.PROMOTION_DENIED)
        try:
            candidate = self._candidate_store.resolve(candidate_key)
        except Exception:
            raise EvaluationLabError(EvaluationLabErrorCode.PROMOTION_DENIED) from None
        with self._lock:
            recorded = self._results.get(held_out_run_id)
            launch = self._launches.get(held_out_run_id)
            verified_security = self._evidence_authority.verify_and_copy_security(security_receipt)
            held_out = recorded.receipt if recorded is not None else None
            dataset = (
                next(
                    (
                        value
                        for value in self._datasets.values()
                        if launch is not None
                        and value.dataset_sha256 == launch.receipt.dataset_sha256
                    ),
                    None,
                )
                if launch is not None
                else None
            )
            if (
                held_out is None
                or launch is None
                or recorded is None
                or dataset is None
                or self._evidence_authority.verify_and_copy_execution(recorded.execution) is None
                or not evaluation_execution_isolated(recorded.execution, launch.receipt.envelope)
                or not execution_matches_run(recorded.execution, held_out, launch)
                or launch_evidence_hash(launch.receipt) != launch.evidence_sha256
                or with_run_evidence(replace(held_out, run_evidence_sha256="0" * 64), launch)
                != held_out
                or held_out.candidate_key != candidate.candidate_key
                or held_out.partition is not EvaluationPartition.LOCKED_TEST
                or held_out.failed_cases != 0
                or held_out.error_cases != 0
                or held_out.denominator_cases < 1
                or held_out.denominator_cases != len(dataset.case_ids)
                or held_out.observed_case_ids != dataset.case_ids
                or held_out.observed_tokens > FIXED_MAX_TOKENS
                or held_out.observed_elapsed_ms > FIXED_MAX_ELAPSED_MS
                or reviewer_id == candidate.submitted_by
                or verified_security is None
                or not verified_security.approved
                or verified_security.reviewer_id != reviewer_id
                or verified_security.actor_id != reviewer_id
                or verified_security.reviewer_id == candidate.submitted_by
                or verified_security.reviewer_id == recorded.execution.actor_id
                or verified_security.run_id != held_out.run_id
                or verified_security.candidate_key != candidate.candidate_key
                or verified_security.candidate_content_sha256 != candidate.content_sha256
                or verified_security.run_evidence_sha256 != held_out.run_evidence_sha256
            ):
                raise EvaluationLabError(EvaluationLabErrorCode.PROMOTION_DENIED)
            return AuthoritativePromotionEvidence(
                held_out.run_id,
                held_out.candidate_key,
                candidate.content_sha256,
                held_out.partition.value,
                held_out.passed_cases,
                held_out.failed_cases,
                held_out.error_cases,
                held_out.denominator_cases,
                held_out.observed_tokens,
                held_out.observed_elapsed_ms,
                held_out.result_sha256,
                held_out.observed_case_ids,
                held_out.run_evidence_sha256,
                verified_security.security_receipt_sha256,
            )

    def _register_dataset(self, dataset: EvaluationDatasetRef) -> None:
        with self._lock:
            existing = self._datasets.get(dataset.dataset_id)
            if existing is not None and existing != dataset:
                raise EvaluationLabError(EvaluationLabErrorCode.LINEAGE_CONFLICT)
            if any(
                item.partition is not dataset.partition
                and item.lineage_sha256 == dataset.lineage_sha256
                for item in self._datasets.values()
            ):
                raise EvaluationLabError(EvaluationLabErrorCode.LINEAGE_CONFLICT)
            self._datasets[dataset.dataset_id] = deepcopy(dataset)


def _capability_for(partition: EvaluationPartition) -> EvaluationCapability:
    return {
        EvaluationPartition.TRAIN: EvaluationCapability.RUN_TRAIN,
        EvaluationPartition.DEV: EvaluationCapability.RUN_DEV,
        EvaluationPartition.CALIBRATION: EvaluationCapability.RUN_CALIBRATION,
        EvaluationPartition.LOCKED_TEST: EvaluationCapability.RUN_LOCKED_TEST,
    }[partition]


__all__ = (  # noqa: SIM905 - compact export list keeps this security module bounded
    "FIXED_MAX_CASES FIXED_MAX_ELAPSED_MS FIXED_MAX_TOKENS AuthoritativePromotionEvidence "
    "EvaluationBudget EvaluationDatasetRef EvaluationEvidenceAuthority EvaluationExecutionReceipt "
    "EvaluationLab EvaluationLabError EvaluationLabErrorCode EvaluationLaunchDisposition "
    "EvaluationLaunchReceipt EvaluationLaunchRequest EvaluationObservedExecution EvaluationPartition "
    "EvaluationPinSet EvaluationPromotionDisposition EvaluationPromotionReceipt "
    "EvaluationPromotionRequest EvaluationRunDisposition EvaluationRunReceipt "
    "EvaluationSandboxEnvelope EvaluationSecurityReceipt"
).split()
