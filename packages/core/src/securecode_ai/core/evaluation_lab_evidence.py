"""Immutable public promotion snapshot and canonical Evaluation Lab hashing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, replace
from typing import NamedTuple, Protocol

from .evaluation_authority import EvaluationExecutionReceipt
from .evaluation_candidate_store import EvaluationCandidateHandle
from .evaluation_lab_models import EvaluationLaunchReceipt, EvaluationRunReceipt

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID_DOMAIN = b"securecode-ai/evaluation-lab/v1\x00"
_CANDIDATE_DOMAIN = b"securecode-ai/evaluation-candidate/v1\x00"
_ENVELOPE_DOMAIN = b"securecode-ai/evaluation-envelope/v1\x00"
_LAUNCH_DOMAIN = b"securecode-ai/evaluation-launch-evidence/v1\x00"
_RUN_EVIDENCE_DOMAIN = b"securecode-ai/evaluation-run-evidence/v1\x00"


class _Dataset(Protocol):
    @property
    def dataset_id(self) -> str: ...
    @property
    def dataset_sha256(self) -> str: ...
    @property
    def lineage_sha256(self) -> str: ...
    @property
    def partition(self) -> object: ...
    @property
    def case_ids(self) -> tuple[str, ...]: ...


class _Pins(Protocol):
    @property
    def model_sha256(self) -> str: ...
    @property
    def policy_sha256(self) -> str: ...
    @property
    def profile_sha256(self) -> str: ...
    @property
    def prompt_sha256(self) -> str: ...
    @property
    def tool_sha256(self) -> str: ...


class _LaunchRequest(Protocol):
    @property
    def candidate_key(self) -> str: ...
    @property
    def dataset(self) -> _Dataset: ...
    @property
    def pins(self) -> _Pins: ...


class _Envelope(Protocol):
    @property
    def network_disabled(self) -> bool: ...
    @property
    def credentials_disabled(self) -> bool: ...
    @property
    def read_only_candidate(self) -> bool: ...
    @property
    def isolated_scratch(self) -> bool: ...
    @property
    def locked_expectations_exposed_to_candidate(self) -> bool: ...

    @property
    def budget(self) -> object: ...


class _Execution(Protocol):
    @property
    def envelope_sha256(self) -> str: ...
    @property
    def network_accessed(self) -> bool: ...
    @property
    def credentials_accessed(self) -> bool: ...
    @property
    def source_disclosed(self) -> bool: ...
    @property
    def locked_expectations_accessed(self) -> bool: ...


class _LaunchedRun(Protocol):
    @property
    def receipt(self) -> EvaluationLaunchReceipt: ...
    @property
    def evidence_sha256(self) -> str: ...


class AuthoritativePromotionEvidence(NamedTuple):
    run_id: str
    candidate_key: str
    candidate_content_sha256: str
    partition: str
    passed_cases: int
    failed_cases: int
    error_cases: int
    denominator_cases: int
    observed_tokens: int
    observed_elapsed_ms: int
    result_sha256: str
    observed_case_ids: tuple[str, ...]
    run_evidence_sha256: str
    security_receipt_sha256: str


def evidence_hash(domain: bytes, material: dict[str, object]) -> str:
    encoded = json.dumps(
        material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def evaluation_run_id(request: _LaunchRequest) -> str:
    partition = getattr(request.dataset.partition, "value", None)
    material: dict[str, object] = {
        "candidate_key": request.candidate_key,
        "dataset": {
            "dataset_id": request.dataset.dataset_id,
            "dataset_sha256": request.dataset.dataset_sha256,
            "lineage_sha256": request.dataset.lineage_sha256,
            "partition": partition,
            "case_ids": request.dataset.case_ids,
        },
        "pins": {
            "model": request.pins.model_sha256,
            "policy": request.pins.policy_sha256,
            "profile": request.pins.profile_sha256,
            "prompt": request.pins.prompt_sha256,
            "tool": request.pins.tool_sha256,
        },
    }
    return "eval-run-" + evidence_hash(_RUN_ID_DOMAIN, material)[:40]


def evaluation_envelope_hash(envelope: _Envelope) -> str:
    budget = envelope.budget
    return evidence_hash(
        _ENVELOPE_DOMAIN,
        {
            "credentials_disabled": envelope.credentials_disabled,
            "isolated_scratch": envelope.isolated_scratch,
            "locked_expectations_exposed_to_candidate": (
                envelope.locked_expectations_exposed_to_candidate
            ),
            "max_cases": getattr(budget, "max_cases", None),
            "max_elapsed_ms": getattr(budget, "max_elapsed_ms", None),
            "max_tokens": getattr(budget, "max_tokens", None),
            "network_disabled": envelope.network_disabled,
            "read_only_candidate": envelope.read_only_candidate,
        },
    )


def evaluation_execution_isolated(execution: _Execution, envelope: _Envelope) -> bool:
    return (
        execution.envelope_sha256 == evaluation_envelope_hash(envelope)
        and not execution.network_accessed
        and not execution.credentials_accessed
        and not execution.source_disclosed
        and not execution.locked_expectations_accessed
    )


def snapshot_candidate(candidate: object) -> EvaluationCandidateHandle:
    if type(candidate) is not EvaluationCandidateHandle:
        raise ValueError("evaluation candidate is invalid")
    snapshot = EvaluationCandidateHandle(
        candidate.candidate_key,
        candidate.candidate_id,
        candidate.submitted_by,
        candidate.lineage_sha256,
        candidate.content_sha256,
        candidate.size_bytes,
    )
    material = "\x00".join(
        (snapshot.candidate_id, snapshot.lineage_sha256, snapshot.content_sha256)
    ).encode("ascii")
    expected_key = "candidate-" + hashlib.sha256(_CANDIDATE_DOMAIN + material).hexdigest()[:40]
    if (
        snapshot.candidate_key != expected_key
        or _ID.fullmatch(snapshot.candidate_id) is None
        or _ID.fullmatch(snapshot.submitted_by) is None
        or _HASH.fullmatch(snapshot.lineage_sha256) is None
        or _HASH.fullmatch(snapshot.content_sha256) is None
        or type(snapshot.size_bytes) is not int
        or snapshot.size_bytes < 1
    ):
        raise ValueError("evaluation candidate is invalid")
    return snapshot


def with_launch_evidence(receipt: EvaluationLaunchReceipt) -> EvaluationLaunchReceipt:
    return replace(receipt, launch_evidence_sha256=launch_evidence_hash(receipt))


def launch_evidence_hash(receipt: EvaluationLaunchReceipt) -> str:
    material = asdict(receipt)
    for field in (
        "disposition",
        "launch_evidence_sha256",
        "locked_expectations_disclosed",
        "source_disclosed",
    ):
        material.pop(field)
    return evidence_hash(_LAUNCH_DOMAIN, material)


def with_run_evidence(receipt: EvaluationRunReceipt, launch: _LaunchedRun) -> EvaluationRunReceipt:
    material = asdict(receipt)
    for field in (
        "disposition",
        "run_evidence_sha256",
        "source_disclosed",
        "locked_expectations_disclosed",
    ):
        material.pop(field)
    launched = launch.receipt
    material["candidate_content_sha256"] = launched.candidate.content_sha256
    material["launch_evidence_sha256"] = launch.evidence_sha256
    return replace(receipt, run_evidence_sha256=evidence_hash(_RUN_EVIDENCE_DOMAIN, material))


def execution_matches_run(
    execution: EvaluationExecutionReceipt,
    receipt: EvaluationRunReceipt,
    launch: _LaunchedRun,
) -> bool:
    return (
        execution.run_id == receipt.run_id
        and execution.launch_evidence_sha256 == launch.evidence_sha256
        and execution.passed_cases == receipt.passed_cases
        and execution.failed_cases == receipt.failed_cases
        and execution.error_cases == receipt.error_cases
        and execution.observed_cases == receipt.denominator_cases
        and execution.observed_case_ids == receipt.observed_case_ids
        and execution.observed_tokens == receipt.observed_tokens
        and execution.observed_elapsed_ms == receipt.observed_elapsed_ms
        and execution.result_sha256 == receipt.result_sha256
        and execution.execution_receipt_sha256 == receipt.execution_receipt_sha256
    )


__all__ = [
    "AuthoritativePromotionEvidence",
    "evaluation_envelope_hash",
    "evaluation_execution_isolated",
    "evaluation_run_id",
    "evidence_hash",
    "execution_matches_run",
    "launch_evidence_hash",
    "snapshot_candidate",
    "with_launch_evidence",
    "with_run_evidence",
]
