"""Executable, no-network oracle contracts for synthetic security cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .synthetic_cases import SyntheticCaseCandidate, SyntheticCaseKind

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
MAX_ORACLE_CASES: Final = 100
MAX_ORACLE_ELAPSED_MS: Final = 60_000


class SyntheticOracleError(ValueError):
    """Safe oracle error without source, expected output, or command text."""

    def __init__(self) -> None:
        super().__init__("Synthetic oracle request was rejected")
        self.__cause__ = None
        self.__context__ = None


class SyntheticOracleDisposition(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class SyntheticOracleDefinition:
    oracle_id: str
    oracle_version: str
    executable_sha256: str
    profile_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.oracle_id) is not str
            or _ID.fullmatch(self.oracle_id) is None
            or type(self.oracle_version) is not str
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.oracle_version) is None
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (self.executable_sha256, self.profile_sha256)
            )
        ):
            raise SyntheticOracleError()


@dataclass(frozen=True, slots=True)
class SyntheticOracleLaunchEnvelope:
    oracle_id: str
    executable_sha256: str
    network_disabled: bool
    credentials_disabled: bool
    read_only_source_artifact: bool
    isolated_scratch: bool
    max_cases: int
    max_elapsed_ms: int

    def __post_init__(self) -> None:
        if (
            type(self.oracle_id) is not str
            or _ID.fullmatch(self.oracle_id) is None
            or type(self.executable_sha256) is not str
            or _HASH.fullmatch(self.executable_sha256) is None
            or self.network_disabled is not True
            or self.credentials_disabled is not True
            or self.read_only_source_artifact is not True
            or self.isolated_scratch is not True
            or self.max_cases != MAX_ORACLE_CASES
            or self.max_elapsed_ms != MAX_ORACLE_ELAPSED_MS
        ):
            raise SyntheticOracleError()


@dataclass(frozen=True, slots=True)
class SyntheticOracleExecution:
    case_id: str
    oracle_id: str
    security_regression_failed: bool
    execution_error: bool
    result_sha256: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.case_id, self.oracle_id)
            )
            or type(self.security_regression_failed) is not bool
            or type(self.execution_error) is not bool
            or type(self.result_sha256) is not str
            or _HASH.fullmatch(self.result_sha256) is None
        ):
            raise SyntheticOracleError()


@dataclass(frozen=True, slots=True)
class SyntheticOracleReceipt:
    case_id: str
    oracle_id: str
    disposition: SyntheticOracleDisposition
    regression_failed: bool
    execution_error: bool
    result_sha256: str
    denominator_cases: int = 1
    source_disclosed: bool = False

    def __post_init__(self) -> None:
        if self.denominator_cases != 1 or self.source_disclosed is not False:
            raise SyntheticOracleError()


def launch_oracle(
    candidate: SyntheticCaseCandidate,
    oracle: SyntheticOracleDefinition,
) -> SyntheticOracleLaunchEnvelope:
    if (
        type(candidate) is not SyntheticCaseCandidate
        or type(oracle) is not SyntheticOracleDefinition
    ):
        raise SyntheticOracleError()
    return SyntheticOracleLaunchEnvelope(
        oracle.oracle_id,
        oracle.executable_sha256,
        True,
        True,
        True,
        True,
        MAX_ORACLE_CASES,
        MAX_ORACLE_ELAPSED_MS,
    )


def evaluate_oracle(
    candidate: SyntheticCaseCandidate,
    oracle: SyntheticOracleDefinition,
    execution: SyntheticOracleExecution,
) -> SyntheticOracleReceipt:
    if (
        type(candidate) is not SyntheticCaseCandidate
        or type(oracle) is not SyntheticOracleDefinition
        or type(execution) is not SyntheticOracleExecution
        or execution.case_id != candidate.case_id
        or execution.oracle_id != oracle.oracle_id
    ):
        raise SyntheticOracleError()
    expected = candidate.kind is SyntheticCaseKind.VULNERABLE
    passed = not execution.execution_error and execution.security_regression_failed is expected
    return SyntheticOracleReceipt(
        candidate.case_id,
        oracle.oracle_id,
        SyntheticOracleDisposition.PASSED if passed else SyntheticOracleDisposition.FAILED,
        execution.security_regression_failed,
        execution.execution_error,
        execution.result_sha256,
    )


__all__ = [
    "MAX_ORACLE_CASES",
    "MAX_ORACLE_ELAPSED_MS",
    "SyntheticOracleDefinition",
    "SyntheticOracleDisposition",
    "SyntheticOracleError",
    "SyntheticOracleExecution",
    "SyntheticOracleLaunchEnvelope",
    "SyntheticOracleReceipt",
    "evaluate_oracle",
    "launch_oracle",
]
