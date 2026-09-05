"""Closed scanner-plugin and execution-budget contracts.

The normative ``RawSignal`` is already defined by the accepted contracts
package. This module wraps that fact rather than creating a second signal type:
scanner execution remains before normalization, candidates, findings, verdicts,
and product outcomes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from securecode_ai.contracts import ProducerRef, RawSignal

from .repository import RepositoryFile

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_MODULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}\Z")
_QUALNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,255}\Z")
_MAX_BUDGETS = (2_000_000, 60_000_000_000, 10_000, 16_384, 1_000_000, 2_000_000)


class ScannerRunStatus(StrEnum):
    """Scanner-stage statuses, intentionally disjoint from product outcomes."""

    SUCCEEDED = "SUCCEEDED"
    TIMEOUT = "TIMEOUT"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    CRASHED = "CRASHED"
    ISOLATION_FAILED = "ISOLATION_FAILED"
    INVALID_OUTPUT = "INVALID_OUTPUT"


class ScannerFailureCode(StrEnum):
    TIME_BUDGET_EXCEEDED = "TIME_BUDGET_EXCEEDED"
    INPUT_BUDGET_EXCEEDED = "INPUT_BUDGET_EXCEEDED"
    SIGNAL_BUDGET_EXCEEDED = "SIGNAL_BUDGET_EXCEEDED"
    OUTPUT_BUDGET_EXCEEDED = "OUTPUT_BUDGET_EXCEEDED"
    PLUGIN_CRASHED = "PLUGIN_CRASHED"
    ISOLATION_REQUIRED = "ISOLATION_REQUIRED"
    WORKER_START_FAILED = "WORKER_START_FAILED"
    PLUGIN_OUTPUT_INVALID = "PLUGIN_OUTPUT_INVALID"


class ScannerIsolationMode(StrEnum):
    """Host-selected boundary; this is process separation, not a sandbox claim."""

    FIRST_PARTY_IN_PROCESS = "FIRST_PARTY_IN_PROCESS"
    APPROVED_ISOLATED_WORKER = "APPROVED_ISOLATED_WORKER"


class ScannerContractError(RuntimeError):
    """Fixed, non-echoing scanner-boundary error."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: ScannerFailureCode) -> None:
        if type(code) is not ScannerFailureCode:
            raise TypeError("scanner failure code is invalid")
        self.code = code
        self.safe_message = "scanner execution did not complete"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class ScannerBudget:
    """Host-owned hard ceilings for one plugin invocation."""

    max_input_bytes: int = _MAX_BUDGETS[0]
    max_elapsed_ns: int = _MAX_BUDGETS[1]
    max_signals: int = _MAX_BUDGETS[2]
    max_fact_bytes: int = _MAX_BUDGETS[3]
    max_output_bytes: int = _MAX_BUDGETS[4]
    max_transport_bytes: int = _MAX_BUDGETS[5]

    def __post_init__(self) -> None:
        values = (
            self.max_input_bytes,
            self.max_elapsed_ns,
            self.max_signals,
            self.max_fact_bytes,
            self.max_output_bytes,
            self.max_transport_bytes,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_BUDGETS, strict=True)
        ):
            raise ValueError("scanner budget is invalid")


DEFAULT_SCANNER_BUDGET = ScannerBudget()


@dataclass(frozen=True, slots=True)
class ScannerIdentity:
    """Host-approved detector provenance for all facts a plugin may emit."""

    producer: ProducerRef

    def __post_init__(self) -> None:
        if type(self.producer) is not ProducerRef:
            raise ValueError("scanner identity is invalid")
        try:
            validated = ProducerRef.model_validate(self.producer.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError):
            raise ValueError("scanner identity is invalid") from None
        if validated != self.producer:
            raise ValueError("scanner identity is invalid")


@dataclass(frozen=True, slots=True)
class ScannerRequest:
    """Exact admitted bytes with no path-opening or network capability."""

    request_id: str
    tenant_id: str
    repository_id: str
    head_sha: str
    file: RepositoryFile
    source: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.request_id) is not str
            or _IDENTIFIER.fullmatch(self.request_id) is None
            or type(self.tenant_id) is not str
            or not self.tenant_id
            or len(self.tenant_id.encode("utf-8")) > 128
            or type(self.repository_id) is not str
            or not self.repository_id
            or len(self.repository_id.encode("utf-8")) > 1024
            or type(self.head_sha) is not str
            or _SHA1.fullmatch(self.head_sha) is None
            or type(self.file) is not RepositoryFile
            or type(self.source) is not bytes
            or len(self.source) != self.file.size_bytes
            or hashlib.sha256(self.source).hexdigest() != self.file.content_sha256
        ):
            raise ValueError("scanner request is invalid")


@dataclass(frozen=True, slots=True)
class ScannerPluginOutput:
    """Plugin-returned normative RawSignal facts only."""

    signals: tuple[RawSignal, ...]

    def __post_init__(self) -> None:
        if type(self.signals) is not tuple or any(
            type(item) is not RawSignal for item in self.signals
        ):
            raise ValueError("scanner plugin output is invalid")


@runtime_checkable
class ScannerPlugin(Protocol):
    """Narrow port with no filesystem, process, shell, or network argument."""

    def scan(self, request: ScannerRequest) -> ScannerPluginOutput: ...


@dataclass(frozen=True, slots=True)
class ScannerWorkerTarget:
    """Host-selected importable factory; never an arbitrary callback object."""

    module: str
    qualname: str

    def __post_init__(self) -> None:
        if (
            type(self.module) is not str
            or _MODULE_NAME.fullmatch(self.module) is None
            or type(self.qualname) is not str
            or _QUALNAME.fullmatch(self.qualname) is None
            or ".." in self.module
            or ".." in self.qualname
        ):
            raise ValueError("scanner worker target is invalid")


@dataclass(frozen=True, slots=True)
class ScannerExecution:
    """Host-issued terminal receipt for a scanner invocation."""

    request_id: str
    scanner: ScannerIdentity
    isolation: ScannerIsolationMode
    status: ScannerRunStatus
    elapsed_ns: int
    input_bytes: int
    output_bytes: int
    signals: tuple[RawSignal, ...]
    signal_digest: str
    failure_code: ScannerFailureCode | None

    def __post_init__(self) -> None:
        valid_signals = (
            type(self.signals) is tuple
            and all(type(item) is RawSignal for item in self.signals)
            and tuple(item.raw_signal_id for item in self.signals)
            == tuple(sorted(item.raw_signal_id for item in self.signals))
            and len({item.raw_signal_id for item in self.signals}) == len(self.signals)
            and all(item.producer == self.scanner.producer for item in self.signals)
            and self.signal_digest == raw_signal_digest(self.signals)
        )
        succeeded = self.status is ScannerRunStatus.SUCCEEDED
        expected_failure = {
            ScannerRunStatus.TIMEOUT: {ScannerFailureCode.TIME_BUDGET_EXCEEDED},
            ScannerRunStatus.RESOURCE_EXHAUSTED: {
                ScannerFailureCode.INPUT_BUDGET_EXCEEDED,
                ScannerFailureCode.SIGNAL_BUDGET_EXCEEDED,
                ScannerFailureCode.OUTPUT_BUDGET_EXCEEDED,
            },
            ScannerRunStatus.CRASHED: {ScannerFailureCode.PLUGIN_CRASHED},
            ScannerRunStatus.ISOLATION_FAILED: {
                ScannerFailureCode.ISOLATION_REQUIRED,
                ScannerFailureCode.WORKER_START_FAILED,
            },
            ScannerRunStatus.INVALID_OUTPUT: {ScannerFailureCode.PLUGIN_OUTPUT_INVALID},
        }
        if (
            type(self.request_id) is not str
            or _IDENTIFIER.fullmatch(self.request_id) is None
            or type(self.scanner) is not ScannerIdentity
            or type(self.isolation) is not ScannerIsolationMode
            or type(self.status) is not ScannerRunStatus
            or type(self.elapsed_ns) is not int
            or self.elapsed_ns < 0
            or type(self.input_bytes) is not int
            or self.input_bytes < 0
            or type(self.output_bytes) is not int
            or self.output_bytes < 0
            or type(self.signal_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.signal_digest) is None
            or not valid_signals
            or (succeeded and self.failure_code is not None)
            or (not succeeded and (self.failure_code is None or self.signals))
            or (self.failure_code is not None and type(self.failure_code) is not ScannerFailureCode)
            or (
                not succeeded
                and self.failure_code is not None
                and self.failure_code not in expected_failure[self.status]
            )
        ):
            raise ValueError("scanner execution is invalid")


def canonical_raw_signal(signal: RawSignal) -> RawSignal:
    """Revalidate an untrusted plugin fact without retaining source bytes."""

    if type(signal) is not RawSignal:
        raise TypeError("raw scanner signal is invalid")
    try:
        return RawSignal.model_validate(signal.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("raw scanner signal is invalid") from None


def raw_signal_payload_bytes(signal: RawSignal) -> int:
    """Return deterministic metadata bytes; RawSignal never embeds source text."""

    canonical = canonical_raw_signal(signal)
    value = canonical.model_dump(mode="json")
    return len(
        json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    )


def raw_signal_digest(signals: tuple[RawSignal, ...]) -> str:
    """Return the host-verifiable digest of canonically ordered signal facts."""

    if type(signals) is not tuple:
        raise TypeError("raw scanner signals are invalid")
    payload = [canonical_raw_signal(signal).model_dump(mode="json") for signal in signals]
    encoded = json.dumps(
        payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "DEFAULT_SCANNER_BUDGET",
    "RawSignal",
    "ScannerBudget",
    "ScannerContractError",
    "ScannerExecution",
    "ScannerFailureCode",
    "ScannerIdentity",
    "ScannerIsolationMode",
    "ScannerPlugin",
    "ScannerPluginOutput",
    "ScannerRequest",
    "ScannerRunStatus",
    "ScannerWorkerTarget",
    "canonical_raw_signal",
    "raw_signal_digest",
    "raw_signal_payload_bytes",
]
