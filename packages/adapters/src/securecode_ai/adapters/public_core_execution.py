"""Pinned public-Core execution measurement without provider admission authority."""

from __future__ import annotations

import http.client
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NoReturn

from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.product_scan import ProductCandidateFlow, ProductCompositionFailure
from securecode_ai.adapters.public_core_runner import (
    PublicCoreDiagnosticSampling,
    PublicCoreHostInputs,
    PublicCoreRunResult,
    prepare_public_core_case,
    run_public_core_case,
)
from securecode_ai.adapters.public_discovery_observation import (
    source_free_discovery_observation_document,
)
from securecode_ai.contracts import ComponentPin, ModelCallStatus
from securecode_ai.core.investigation import AuditorInvestigationReceipt

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_VERSION: Final = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_MODEL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")


class PublicCoreExecutionError(ValueError):
    """Fixed non-echoing execution-boundary failure."""

    def __init__(self) -> None:
        super().__init__("public Core execution measurement failed")
        self.__cause__ = None
        self.__context__ = None


def _fail() -> NoReturn:
    raise PublicCoreExecutionError()


@dataclass(frozen=True, slots=True)
class BackendIdentity:
    """Exact host-derived identity expected before and after an execution attempt."""

    model_id: str
    model_manifest_sha256: str
    backend_version: str
    backend_executable_sha256: str
    gateway_source_sha256: str
    gateway_policy_sha256: str
    connector_source_sha256: str
    backend_authority: str
    backend_port: int
    gateway_port: int

    def __post_init__(self) -> None:
        values = (
            self.model_manifest_sha256,
            self.backend_executable_sha256,
            self.gateway_source_sha256,
            self.gateway_policy_sha256,
            self.connector_source_sha256,
        )
        if (
            type(self.model_id) is not str
            or _MODEL.fullmatch(self.model_id) is None
            or type(self.backend_version) is not str
            or _VERSION.fullmatch(self.backend_version) is None
            or any(type(item) is not str or _SHA256.fullmatch(item) is None for item in values)
            or type(self.backend_authority) is not str
            or self.backend_authority != "127.0.0.1"
            or any(
                type(item) is not int or isinstance(item, bool) or not 1 <= item <= 65535
                for item in (self.backend_port, self.gateway_port)
            )
            or self.backend_port == self.gateway_port
        ):
            _fail()

    def snapshot(self) -> BackendIdentity:
        return BackendIdentity(
            model_id=self.model_id,
            model_manifest_sha256=self.model_manifest_sha256,
            backend_version=self.backend_version,
            backend_executable_sha256=self.backend_executable_sha256,
            gateway_source_sha256=self.gateway_source_sha256,
            gateway_policy_sha256=self.gateway_policy_sha256,
            connector_source_sha256=self.connector_source_sha256,
            backend_authority=self.backend_authority,
            backend_port=self.backend_port,
            gateway_port=self.gateway_port,
        )


@dataclass(frozen=True, slots=True)
class BackendObservation:
    """Host-derived listener metadata.  It is evidence, never a LIVE assertion."""

    identity: BackendIdentity
    listener_pid: int
    listener_executable_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not BackendIdentity
            or type(self.listener_pid) is not int
            or isinstance(self.listener_pid, bool)
            or self.listener_pid < 1
            or type(self.listener_executable_sha256) is not str
            or _SHA256.fullmatch(self.listener_executable_sha256) is None
            or self.listener_executable_sha256 != self.identity.backend_executable_sha256
        ):
            _fail()
        object.__setattr__(self, "identity", self.identity.snapshot())


class ExecutionOrigin(StrEnum):
    UNQUALIFIED_ACTUAL = "UNQUALIFIED_ACTUAL"
    SIMULATED = "SIMULATED"


@dataclass(frozen=True, slots=True)
class PublicCoreExecutionResult:
    """Source-free measurement state.  It cannot authorize a provider or capability."""

    case: CoreCase
    origin: ExecutionOrigin
    expected_backend: BackendIdentity
    provider_profile: ComponentPin
    configuration: ComponentPin
    diagnostic_sampling: PublicCoreDiagnosticSampling | None
    before: BackendObservation | None
    after: BackendObservation | None
    pre_execution_match: bool
    post_execution_match: bool | None
    fixture_recipe_sha256: str | None
    fixture_head_sha: str | None
    fixture_manifest: tuple[tuple[str, str], ...]
    request_identity_sha256: str | None
    request_prompt_sha256: str | None
    request_schema_sha256: str | None
    run: PublicCoreRunResult | None
    failure_code: str | None

    @property
    def measurement_valid(self) -> bool:
        return (
            self.pre_execution_match
            and self.post_execution_match is True
            and self.failure_code is None
        )

    @property
    def production_admitted(self) -> bool:
        return False


def _observe(observer: Callable[[], BackendObservation]) -> BackendObservation:
    if not callable(observer):
        _fail()
    try:
        value = observer()
        if type(value) is not BackendObservation:
            _fail()
        return BackendObservation(
            value.identity, value.listener_pid, value.listener_executable_sha256
        )
    except (
        TypeError,
        ValueError,
        OSError,
        TimeoutError,
        http.client.HTTPException,
        subprocess.SubprocessError,
    ):
        _fail()


def _binding(
    case: CoreCase, inputs: PublicCoreHostInputs
) -> tuple[str, str, tuple[tuple[str, str], ...], str, str, str]:
    prepared = prepare_public_core_case(case=case, inputs=inputs)
    fixture = prepared.fixture
    return (
        fixture.recipe_sha256,
        fixture.head_sha,
        tuple((item.path, item.content_sha256) for item in fixture.source_manifest_hashes),
        prepared.request.execution_identity.execution_identity_hash,
        prepared.request.prompt.content_sha256,
        prepared.request.output_schema.content_sha256,
    )


def _result(
    *,
    case: CoreCase,
    origin: ExecutionOrigin,
    expected: BackendIdentity,
    inputs: PublicCoreHostInputs,
    before: BackendObservation | None,
    after: BackendObservation | None,
    pre_match: bool,
    post_match: bool | None,
    binding: tuple[str, str, tuple[tuple[str, str], ...], str, str, str] | None,
    run: PublicCoreRunResult | None,
    failure_code: str | None,
) -> PublicCoreExecutionResult:
    recipe: str | None
    head: str | None
    manifest: tuple[tuple[str, str], ...]
    identity: str | None
    prompt: str | None
    schema: str | None
    if binding is None:
        recipe, head, manifest, identity, prompt, schema = None, None, (), None, None, None
    else:
        recipe, head, manifest, identity, prompt, schema = binding
    return PublicCoreExecutionResult(
        case,
        origin,
        expected,
        inputs.provider_pin,
        inputs.artifacts.configuration,
        inputs.diagnostic_sampling,
        before,
        after,
        pre_match,
        post_match,
        recipe,
        head,
        manifest,
        identity,
        prompt,
        schema,
        run,
        failure_code,
    )


def execute_public_core_case(
    *,
    case: CoreCase,
    inputs: PublicCoreHostInputs,
    expected_backend: BackendIdentity,
    observe_backend: Callable[[], BackendObservation],
    simulated_transport: object | None = None,
) -> PublicCoreExecutionResult:
    """Measure one configured run with exact before/after host identity pins."""
    if (
        type(case) is not CoreCase
        or type(inputs) is not PublicCoreHostInputs
        or type(expected_backend) is not BackendIdentity
    ):
        _fail()
    try:
        inputs = inputs.snapshot()
    except (TypeError, ValueError):
        _fail()
    expected = expected_backend.snapshot()
    if (
        expected.model_id != inputs.profile.model_id
        or expected.model_manifest_sha256 != inputs.profile.model_snapshot
        or expected.gateway_port != inputs.gateway_port
    ):
        _fail()
    origin = (
        ExecutionOrigin.SIMULATED
        if simulated_transport is not None
        else ExecutionOrigin.UNQUALIFIED_ACTUAL
    )
    try:
        before = _observe(observe_backend)
    except PublicCoreExecutionError:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=None,
            after=None,
            pre_match=False,
            post_match=None,
            binding=None,
            run=None,
            failure_code="PRE_OBSERVATION_FAILED",
        )
    if before.identity != expected:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=before,
            after=None,
            pre_match=False,
            post_match=None,
            binding=None,
            run=None,
            failure_code="PRE_IDENTITY_MISMATCH",
        )
    try:
        binding = _binding(case, inputs)
        run = run_public_core_case(
            case=case, inputs=inputs, simulated_transport=simulated_transport
        )
    except (TypeError, ValueError, RuntimeError):
        binding, run = None, None
    try:
        after = _observe(observe_backend)
    except PublicCoreExecutionError:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=before,
            after=None,
            pre_match=True,
            post_match=False,
            binding=binding,
            run=run,
            failure_code="POST_OBSERVATION_FAILED",
        )
    if after.identity != expected:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=before,
            after=after,
            pre_match=True,
            post_match=False,
            binding=binding,
            run=run,
            failure_code="POST_IDENTITY_MISMATCH",
        )
    if after.listener_pid != before.listener_pid:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=before,
            after=after,
            pre_match=True,
            post_match=False,
            binding=binding,
            run=run,
            failure_code="POST_LISTENER_CHANGED",
        )
    if run is None:
        return _result(
            case=case,
            origin=origin,
            expected=expected,
            inputs=inputs,
            before=before,
            after=after,
            pre_match=True,
            post_match=True,
            binding=binding,
            run=None,
            failure_code="EXECUTION_FAILED",
        )
    return _result(
        case=case,
        origin=origin,
        expected=expected,
        inputs=inputs,
        before=before,
        after=after,
        pre_match=True,
        post_match=True,
        binding=binding,
        run=run,
        failure_code=None,
    )


def _usage(flow: ProductCandidateFlow | ProductCompositionFailure | None) -> dict[str, object]:
    if type(flow) is not ProductCandidateFlow:
        return {"known": False, "tokens_used": None, "elapsed_ms": None}
    receipt = flow.discovery.receipt
    usage = receipt.budget_usage
    elapsed = usage.elapsed_ms if type(usage.elapsed_ms) is int and usage.elapsed_ms >= 0 else None
    if receipt.model_call_status is not ModelCallStatus.SUCCEEDED:
        # A discarded result leaves a default zero counter, not measured latency.
        return {"known": False, "tokens_used": None, "elapsed_ms": elapsed if elapsed else None}
    if type(usage.tokens_used) is not int or usage.tokens_used < 0:
        return {"known": False, "tokens_used": None, "elapsed_ms": elapsed}
    return {"known": True, "tokens_used": usage.tokens_used, "elapsed_ms": elapsed}


def _pin_document(pin: ComponentPin) -> dict[str, str]:
    return {
        "component_id": pin.component_id,
        "component_version": pin.component_version,
        "content_sha256": pin.content_sha256,
    }


def _sampling_document(
    sampling: PublicCoreDiagnosticSampling | None,
) -> dict[str, object]:
    if sampling is None:
        return {
            "enabled": False,
            "applies_to": None,
            "temperature": None,
            "seed": None,
            "model_id": None,
            "model_snapshot": None,
        }
    return {
        "enabled": True,
        "applies_to": "native_discovery",
        "temperature": sampling.temperature,
        "seed": sampling.seed,
        "model_id": sampling.model_id,
        "model_snapshot": sampling.model_snapshot,
    }


def source_free_execution_document(result: PublicCoreExecutionResult) -> dict[str, object]:
    """Whitelist durable diagnostic metadata and omit graph, source and provider payloads."""
    if type(result) is not PublicCoreExecutionResult:
        _fail()
    flow = result.run.flow if result.run is not None else None
    discovery: dict[str, object] = {"state": "NOT_EXECUTED", "candidate_count": 0}
    auditors: list[dict[str, object]] = []
    if type(flow) is ProductCandidateFlow:
        discovery = {
            "state": flow.discovery.receipt.model_call_status.value,
            "candidate_count": len(flow.discovery.candidates),
            "required_terminal_outcome": None
            if flow.discovery.required_terminal_outcome is None
            else flow.discovery.required_terminal_outcome.value,
        }
        for receipt in flow.investigations:
            if isinstance(receipt, AuditorInvestigationReceipt):
                auditors.append(
                    {
                        "model_call_status": receipt.final_model_call_status.value,
                        "finding_verdict": receipt.finding_verdict.value,
                        "tokens_used": receipt.tokens_used,
                        "tool_calls": receipt.tool_calls,
                        "elapsed_ms": receipt.elapsed_ms,
                    }
                )
            else:
                auditors.append({"model_call_status": "PREPARATION_FAILED"})
    elif type(flow) is ProductCompositionFailure:
        discovery = {"state": "COMPOSITION_FAILED", "candidate_count": 0}
    return {
        "schema_version": "securecode.release-checkpoint.v1",
        "case": result.case.value,
        "origin": result.origin.value,
        "production_admitted": False,
        "measurement_valid": result.measurement_valid,
        "failure_code": result.failure_code,
        "core_completed": False if result.run is None else result.run.completed,
        "core_failure_code": None if result.run is None else result.run.failure_code,
        "identity": {
            "pre_execution_match": result.pre_execution_match,
            "post_execution_match": result.post_execution_match,
            "model_id": result.expected_backend.model_id,
            "model_manifest_sha256": result.expected_backend.model_manifest_sha256,
            "backend_version": result.expected_backend.backend_version,
            "backend_executable_sha256": result.expected_backend.backend_executable_sha256,
            "gateway_source_sha256": result.expected_backend.gateway_source_sha256,
            "gateway_policy_sha256": result.expected_backend.gateway_policy_sha256,
            "connector_source_sha256": result.expected_backend.connector_source_sha256,
            "backend_authority": result.expected_backend.backend_authority,
            "backend_port": result.expected_backend.backend_port,
            "gateway_port": result.expected_backend.gateway_port,
            "before_listener_pid": None if result.before is None else result.before.listener_pid,
            "after_listener_pid": None if result.after is None else result.after.listener_pid,
        },
        "fixture": {
            "recipe_sha256": result.fixture_recipe_sha256,
            "head_sha": result.fixture_head_sha,
            "manifest": [
                {"path": path, "content_sha256": digest} for path, digest in result.fixture_manifest
            ],
        },
        "request": {
            "execution_identity_sha256": result.request_identity_sha256,
            "prompt_sha256": result.request_prompt_sha256,
            "schema_sha256": result.request_schema_sha256,
        },
        "provider_profile": _pin_document(result.provider_profile),
        "configuration": _pin_document(result.configuration),
        "sampling": _sampling_document(result.diagnostic_sampling),
        "discovery": discovery,
        "auditors": auditors,
        "discovery_usage": _usage(flow),
        "discovery_observation": None
        if result.run is None or result.run.discovery_observation is None
        else source_free_discovery_observation_document(result.run.discovery_observation),
    }


__all__ = [
    "BackendIdentity",
    "BackendObservation",
    "ExecutionOrigin",
    "PublicCoreExecutionError",
    "PublicCoreExecutionResult",
    "execute_public_core_case",
    "source_free_execution_document",
]
