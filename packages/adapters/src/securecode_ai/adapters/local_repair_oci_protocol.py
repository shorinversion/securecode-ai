"""Closed, source-free wire receipts for installed local OCI repair validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Final

from securecode_ai.core.regression import (
    RegressionCaseResult,
    RegressionExpectedOutcome,
    RegressionObservationStatus,
)

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IMAGE: Final = re.compile(r"(?:[^\s@]+@)?(?P<digest>sha256:[0-9a-f]{64})\Z")
_MAX_RECEIPT_BYTES: Final = 131_072
_PREPARE_DOMAIN: Final = b"securecode-ai/local-repair-oci-prepare/v1\x00"
_STAGE_DOMAIN: Final = b"securecode-ai/local-repair-oci-stage/v1\x00"


class LocalRepairOciProtocolError(ValueError):
    """Fixed protocol failure which never echoes child output."""

    def __init__(self, reason: str = "OCI_PROTOCOL_INVALID") -> None:
        self.reason = reason
        super().__init__("local repair OCI protocol failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class OciPreparationReceipt:
    parent_head_sha: str
    fixed_head_sha: str
    patch_sha256: str
    bundle_sha256: str
    image_digest: str
    observations: tuple[RegressionCaseResult, ...]
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class OciStageReceipt:
    stage_id: str
    parent_head_sha: str
    fixed_head_sha: str
    patch_sha256: str
    bundle_sha256: str
    image_digest: str
    exit_code: int
    elapsed_ms: int
    cpu_time_ms: int
    peak_memory_bytes: int
    disk_bytes: int
    processes_peak: int
    network_packets: int
    oom_killed: bool
    timed_out: bool
    result_sha256: str
    receipt_sha256: str

    def public_bytes(self) -> bytes:
        """Return only the bounded metadata consumed by the sandbox receipt."""

        return canonical_json(
            {
                "bundle_sha256": self.bundle_sha256,
                "exit_code": self.exit_code,
                "fixed_head_sha": self.fixed_head_sha,
                "image_digest": self.image_digest,
                "patch_sha256": self.patch_sha256,
                "receipt_sha256": self.receipt_sha256,
                "result_sha256": self.result_sha256,
                "schema_version": "1.0.0",
                "stage_id": self.stage_id,
            }
        )


def build_preparation_document(
    *,
    parent_head_sha: str,
    fixed_head_sha: str,
    patch_sha256: str,
    bundle_sha256: str,
    selected_image_digest: str,
    observations: tuple[RegressionCaseResult, ...],
) -> bytes:
    material = {
        "bundle_sha256": _sha(bundle_sha256),
        "fixed_head_sha": _commit(fixed_head_sha),
        "image_digest": _digest(selected_image_digest),
        "observations": [_observation_document(item) for item in observations],
        "parent_head_sha": _commit(parent_head_sha),
        "patch_sha256": _sha(patch_sha256),
        "schema_version": "1.0.0",
    }
    return canonical_json({**material, "receipt_sha256": _hash(_PREPARE_DOMAIN, material)})


def build_stage_document(
    *,
    stage_id: str,
    parent_head_sha: str,
    fixed_head_sha: str,
    patch_sha256: str,
    bundle_sha256: str,
    selected_image_digest: str,
    exit_code: int,
    elapsed_ms: int,
    cpu_time_ms: int,
    peak_memory_bytes: int,
    disk_bytes: int,
    processes_peak: int,
    network_packets: int,
    oom_killed: bool,
    timed_out: bool,
    result_sha256: str,
) -> bytes:
    material = {
        "bundle_sha256": _sha(bundle_sha256),
        "cpu_time_ms": _integer(cpu_time_ms, minimum=0),
        "disk_bytes": _integer(disk_bytes, minimum=0),
        "elapsed_ms": _integer(elapsed_ms, minimum=0),
        "exit_code": _integer(exit_code, minimum=0, maximum=255),
        "fixed_head_sha": _commit(fixed_head_sha),
        "image_digest": _digest(selected_image_digest),
        "network_packets": _integer(network_packets, minimum=0),
        "oom_killed": _boolean(oom_killed),
        "parent_head_sha": _commit(parent_head_sha),
        "patch_sha256": _sha(patch_sha256),
        "peak_memory_bytes": _integer(peak_memory_bytes, minimum=0),
        "processes_peak": _integer(processes_peak, minimum=0),
        "result_sha256": _sha(result_sha256),
        "schema_version": "1.0.0",
        "stage_id": _identifier(stage_id),
        "timed_out": _boolean(timed_out),
    }
    return canonical_json({**material, "receipt_sha256": _hash(_STAGE_DOMAIN, material)})


def image_digest(reference: str) -> str:
    if type(reference) is not str:
        raise LocalRepairOciProtocolError("OCI_IMAGE_INVALID")
    match = _IMAGE.fullmatch(reference)
    if match is None:
        raise LocalRepairOciProtocolError("OCI_IMAGE_NOT_PINNED")
    return match.group("digest")


def parse_preparation_receipt(
    raw: bytes,
    *,
    parent_head_sha: str,
    patch_sha256: str,
    bundle_sha256: str,
    expected_image_digest: str,
    expected_case_ids: tuple[str, ...],
) -> OciPreparationReceipt:
    document = closed_json(raw)
    required = {
        "bundle_sha256",
        "fixed_head_sha",
        "image_digest",
        "observations",
        "parent_head_sha",
        "patch_sha256",
        "receipt_sha256",
        "schema_version",
    }
    if set(document) != required or document.get("schema_version") != "1.0.0":
        raise LocalRepairOciProtocolError()
    observations = _observations(document.get("observations"), expected_case_ids)
    material = {key: document[key] for key in sorted(required - {"receipt_sha256"})}
    receipt = OciPreparationReceipt(
        parent_head_sha=_commit(document.get("parent_head_sha")),
        fixed_head_sha=_commit(document.get("fixed_head_sha")),
        patch_sha256=_sha(document.get("patch_sha256")),
        bundle_sha256=_sha(document.get("bundle_sha256")),
        image_digest=_digest(document.get("image_digest")),
        observations=observations,
        receipt_sha256=_sha(document.get("receipt_sha256")),
    )
    if (
        receipt.parent_head_sha != parent_head_sha
        or receipt.fixed_head_sha == parent_head_sha
        or receipt.patch_sha256 != patch_sha256
        or receipt.bundle_sha256 != bundle_sha256
        or receipt.image_digest != expected_image_digest
        or receipt.receipt_sha256 != _hash(_PREPARE_DOMAIN, material)
    ):
        raise LocalRepairOciProtocolError("OCI_PREPARATION_IDENTITY_MISMATCH")
    return receipt


def parse_stage_receipt(
    raw: bytes,
    *,
    stage_id: str,
    parent_head_sha: str,
    fixed_head_sha: str,
    patch_sha256: str,
    bundle_sha256: str,
    expected_image_digest: str,
) -> OciStageReceipt:
    document = closed_json(raw)
    required = {
        "bundle_sha256",
        "cpu_time_ms",
        "disk_bytes",
        "elapsed_ms",
        "exit_code",
        "fixed_head_sha",
        "image_digest",
        "network_packets",
        "oom_killed",
        "parent_head_sha",
        "patch_sha256",
        "peak_memory_bytes",
        "processes_peak",
        "receipt_sha256",
        "result_sha256",
        "schema_version",
        "stage_id",
        "timed_out",
    }
    if set(document) != required or document.get("schema_version") != "1.0.0":
        raise LocalRepairOciProtocolError()
    receipt = OciStageReceipt(
        stage_id=_identifier(document.get("stage_id")),
        parent_head_sha=_commit(document.get("parent_head_sha")),
        fixed_head_sha=_commit(document.get("fixed_head_sha")),
        patch_sha256=_sha(document.get("patch_sha256")),
        bundle_sha256=_sha(document.get("bundle_sha256")),
        image_digest=_digest(document.get("image_digest")),
        exit_code=_integer(document.get("exit_code"), minimum=0, maximum=255),
        elapsed_ms=_integer(document.get("elapsed_ms"), minimum=0),
        cpu_time_ms=_integer(document.get("cpu_time_ms"), minimum=0),
        peak_memory_bytes=_integer(document.get("peak_memory_bytes"), minimum=0),
        disk_bytes=_integer(document.get("disk_bytes"), minimum=0),
        processes_peak=_integer(document.get("processes_peak"), minimum=0),
        network_packets=_integer(document.get("network_packets"), minimum=0),
        oom_killed=_boolean(document.get("oom_killed")),
        timed_out=_boolean(document.get("timed_out")),
        result_sha256=_sha(document.get("result_sha256")),
        receipt_sha256=_sha(document.get("receipt_sha256")),
    )
    material = {key: document[key] for key in sorted(required - {"receipt_sha256"})}
    if (
        receipt.stage_id != stage_id
        or receipt.parent_head_sha != parent_head_sha
        or receipt.fixed_head_sha != fixed_head_sha
        or receipt.patch_sha256 != patch_sha256
        or receipt.bundle_sha256 != bundle_sha256
        or receipt.image_digest != expected_image_digest
        or receipt.receipt_sha256 != _hash(_STAGE_DOMAIN, material)
    ):
        raise LocalRepairOciProtocolError("OCI_STAGE_IDENTITY_MISMATCH")
    return receipt


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise LocalRepairOciProtocolError() from None


def closed_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_RECEIPT_BYTES:
        raise LocalRepairOciProtocolError()

    def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result or "\x00" in key:
                raise LocalRepairOciProtocolError()
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=closed)
    except LocalRepairOciProtocolError:
        raise
    except Exception:
        raise LocalRepairOciProtocolError() from None
    if type(value) is not dict:
        raise LocalRepairOciProtocolError()
    return dict(value)


def _observations(
    value: object, expected_case_ids: tuple[str, ...]
) -> tuple[RegressionCaseResult, ...]:
    if type(value) is not list or len(value) != len(expected_case_ids):
        raise LocalRepairOciProtocolError("OCI_REGRESSION_RECEIPT_INVALID")
    results: list[RegressionCaseResult] = []
    for item in value:
        if type(item) is not dict or set(item) != {
            "case_id",
            "observed_outcome",
            "output_sha256",
            "output_size_bytes",
            "status",
        }:
            raise LocalRepairOciProtocolError("OCI_REGRESSION_RECEIPT_INVALID")
        try:
            status = RegressionObservationStatus(item["status"])
            outcome = (
                RegressionExpectedOutcome(item["observed_outcome"])
                if item["observed_outcome"] is not None
                else None
            )
            results.append(
                RegressionCaseResult(
                    case_id=_identifier(item["case_id"]),
                    status=status,
                    observed_outcome=outcome,
                    output_sha256=(
                        _sha(item["output_sha256"]) if item["output_sha256"] is not None else None
                    ),
                    output_size_bytes=_integer(
                        item["output_size_bytes"], minimum=0, maximum=_MAX_RECEIPT_BYTES
                    ),
                )
            )
        except (TypeError, ValueError):
            raise LocalRepairOciProtocolError("OCI_REGRESSION_RECEIPT_INVALID") from None
    ordered = tuple(sorted(results, key=lambda item: item.case_id))
    if tuple(item.case_id for item in ordered) != tuple(sorted(expected_case_ids)):
        raise LocalRepairOciProtocolError("OCI_REGRESSION_RECEIPT_INVALID")
    return ordered


def _observation_document(value: RegressionCaseResult) -> dict[str, object]:
    if type(value) is not RegressionCaseResult:
        raise LocalRepairOciProtocolError("OCI_REGRESSION_RECEIPT_INVALID")
    return {
        "case_id": value.case_id,
        "observed_outcome": value.observed_outcome.value if value.observed_outcome else None,
        "output_sha256": value.output_sha256,
        "output_size_bytes": value.output_size_bytes,
        "status": value.status.value,
    }


def _identifier(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise LocalRepairOciProtocolError()
    return value


def _sha(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise LocalRepairOciProtocolError()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise LocalRepairOciProtocolError()
    return value


def _commit(value: object) -> str:
    if type(value) is not str or _COMMIT.fullmatch(value) is None:
        raise LocalRepairOciProtocolError()
    return value


def _integer(value: object, *, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise LocalRepairOciProtocolError()
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise LocalRepairOciProtocolError()
    return value


def _hash(domain: bytes, material: object) -> str:
    return hashlib.sha256(domain + canonical_json(material)).hexdigest()


__all__ = [
    "LocalRepairOciProtocolError",
    "OciPreparationReceipt",
    "OciStageReceipt",
    "build_preparation_document",
    "build_stage_document",
    "canonical_json",
    "closed_json",
    "image_digest",
    "parse_preparation_receipt",
    "parse_stage_receipt",
]
