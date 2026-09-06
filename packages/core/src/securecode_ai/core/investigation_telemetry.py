"""Immutable, source-free telemetry contracts for investigation replay.

This module deliberately has no dependency on the investigation workflow.  It
stores identifiers, hashes and aggregate counters only; prompts, responses,
tool payloads and source material never enter the model.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ModelCallStatus

_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991


class TelemetryValidationError(ValueError):
    """Safe validation failure which never includes supplied content."""


class NodeKind(StrEnum):
    DISCOVERY = "DISCOVERY"
    INVESTIGATION = "INVESTIGATION"
    SKEPTIC = "SKEPTIC"
    ROUTER = "ROUTER"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class TelemetryUsage:
    """Aggregate provider usage; all values are non-negative integers."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    input_bytes: int = 0
    output_bytes: int = 0

    def __post_init__(self) -> None:
        values = (
            self.calls,
            self.input_tokens,
            self.output_tokens,
            self.input_bytes,
            self.output_bytes,
        )
        if any(type(v) is not int or not 0 <= v <= _MAX_SAFE_INTEGER for v in values):
            raise TelemetryValidationError("usage counters are invalid")


@dataclass(frozen=True, slots=True)
class NodeTelemetry:
    """One node measurement, with no node input/output content."""

    node_id: str
    node_kind: NodeKind
    attempt: int
    status: ModelCallStatus
    latency_ms: int
    usage: TelemetryUsage = TelemetryUsage()

    def __post_init__(self) -> None:
        if not _valid_id(self.node_id) or type(self.node_kind) is not NodeKind:
            raise TelemetryValidationError("node identity is invalid")
        if type(self.status) is not ModelCallStatus:
            raise TelemetryValidationError("node status is invalid")
        _positive(self.attempt, "node attempt")
        _nonnegative(self.latency_ms, "node latency")
        if type(self.usage) is not TelemetryUsage:
            raise TelemetryValidationError("node usage is invalid")


@dataclass(frozen=True, slots=True)
class InvestigationTelemetry:
    """Exact-version, replay-complete metadata for one investigation attempt."""

    tenant_id: str
    run_id: str
    head_sha: str
    execution_identity_hash: str
    provider: str
    model: str
    profile: str
    prompt_schema_hash: str
    output_schema_hash: str
    tool_policy_hash: str
    evidence_package_hash: str
    package_hash: str
    route_hash: str
    idempotency_key: str
    attempt: int
    status: ModelCallStatus
    usage: TelemetryUsage
    latency_ms: int
    cost_microunits: int
    node: NodeTelemetry
    schema_version: str = CONTRACT_SCHEMA_VERSION
    replay_digest: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_SCHEMA_VERSION:
            raise TelemetryValidationError("telemetry schema version is invalid")
        for value, label in (
            (self.tenant_id, "tenant"),
            (self.run_id, "run"),
            (self.provider, "provider"),
            (self.model, "model"),
            (self.profile, "profile"),
            (self.idempotency_key, "idempotency key"),
        ):
            if not _valid_id(value):
                raise TelemetryValidationError(f"{label} is invalid")
        if not _COMMIT_SHA.fullmatch(self.head_sha):
            raise TelemetryValidationError("HEAD hash is invalid")
        for value, label in (
            (self.execution_identity_hash, "execution identity"),
            (self.prompt_schema_hash, "prompt schema"),
            (self.output_schema_hash, "output schema"),
            (self.tool_policy_hash, "tool policy"),
            (self.evidence_package_hash, "evidence package"),
            (self.package_hash, "package"),
            (self.route_hash, "route"),
        ):
            if not _SHA256.fullmatch(value):
                raise TelemetryValidationError(f"{label} hash is invalid")
        if type(self.status) is not ModelCallStatus:
            raise TelemetryValidationError("status is invalid")
        if type(self.usage) is not TelemetryUsage or type(self.node) is not NodeTelemetry:
            raise TelemetryValidationError("nested telemetry is invalid")
        _positive(self.attempt, "attempt")
        _nonnegative(self.latency_ms, "latency")
        _nonnegative(self.cost_microunits, "cost")
        expected = self._digest_for()
        if self.replay_digest and self.replay_digest != expected:
            raise TelemetryValidationError("replay digest does not match canonical metadata")
        object.__setattr__(self, "replay_digest", expected)

    def _document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "head_sha": self.head_sha,
            "execution_identity_hash": self.execution_identity_hash,
            "provider": self.provider,
            "model": self.model,
            "profile": self.profile,
            "prompt_schema_hash": self.prompt_schema_hash,
            "output_schema_hash": self.output_schema_hash,
            "tool_policy_hash": self.tool_policy_hash,
            "evidence_package_hash": self.evidence_package_hash,
            "package_hash": self.package_hash,
            "route_hash": self.route_hash,
            "idempotency_key": self.idempotency_key,
            "attempt": self.attempt,
            "status": self.status.value,
            "usage": {
                "calls": self.usage.calls,
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "input_bytes": self.usage.input_bytes,
                "output_bytes": self.usage.output_bytes,
            },
            "latency_ms": self.latency_ms,
            "cost_microunits": self.cost_microunits,
            "node": {
                "node_id": self.node.node_id,
                "node_kind": self.node.node_kind.value,
                "attempt": self.node.attempt,
                "status": self.node.status.value,
                "latency_ms": self.node.latency_ms,
                "usage": {
                    "calls": self.node.usage.calls,
                    "input_tokens": self.node.usage.input_tokens,
                    "output_tokens": self.node.usage.output_tokens,
                    "input_bytes": self.node.usage.input_bytes,
                    "output_bytes": self.node.usage.output_bytes,
                },
            },
        }

    def _digest_for(self) -> str:
        payload = json.dumps(
            self._document(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                {**self._document(), "replay_digest": self.replay_digest},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()

    @property
    def is_success(self) -> bool:
        return self.status is ModelCallStatus.SUCCEEDED

    @property
    def canonical_replay_digest(self) -> str:
        return self.replay_digest


@dataclass(frozen=True, slots=True)
class InvestigationTrace:
    records: tuple[InvestigationTelemetry, ...] = ()

    def __post_init__(self) -> None:
        if type(self.records) is not tuple or any(
            type(r) is not InvestigationTelemetry for r in self.records
        ):
            raise TelemetryValidationError("trace records are invalid")
        keys = [(r.tenant_id, r.run_id, r.head_sha, r.idempotency_key) for r in self.records]
        if len(keys) != len(set(keys)):
            raise TelemetryValidationError("trace contains duplicate idempotency keys")
        scopes = {
            (r.tenant_id, r.run_id, r.head_sha, r.execution_identity_hash) for r in self.records
        }
        if len(scopes) > 1:
            raise TelemetryValidationError("trace records have different execution scopes")

    @property
    def replay_digest(self) -> str:
        payload = b"".join(record.canonical_bytes() for record in self.records)
        return hashlib.sha256(payload).hexdigest()

    def complete_for(self, node_ids: tuple[str, ...]) -> bool:
        seen = {record.node.node_id for record in self.records}
        return all(_valid_id(node_id) and node_id in seen for node_id in node_ids)

    @property
    def trace_complete(self) -> bool:
        return bool(self.records) and all(
            record.status is ModelCallStatus.SUCCEEDED for record in self.records
        )


def replay_trace(records: tuple[InvestigationTelemetry, ...]) -> InvestigationTrace:
    """Reconstruct a trace from immutable records and return its canonical projection."""

    return InvestigationTrace(records=tuple(records))


def _valid_id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _nonnegative(value: object, label: str) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise TelemetryValidationError(f"{label} is invalid")


def _positive(value: object, label: str) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise TelemetryValidationError(f"{label} is invalid")


__all__ = [
    "InvestigationTelemetry",
    "InvestigationTrace",
    "NodeKind",
    "NodeTelemetry",
    "TelemetryUsage",
    "TelemetryValidationError",
    "replay_trace",
]
