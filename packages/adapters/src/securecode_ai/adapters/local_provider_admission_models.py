"""Receipt-bound host admission, not runtime attestation or repository authority.

Only trusted host composition may construct ``TrustedLocalProviderAdmission``
and supply independently reviewed pins. Receipt imports cannot construct that
authority or change its approved hashes. No keys or network effects exist here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from enum import StrEnum
from typing import Final, NoReturn, Self, SupportsIndex

from pydantic import Field, field_validator
from securecode_ai.contracts import (
    ApiDialect,
    ComponentPin,
    DiscoveryCandidate,
    ExecutionBoundary,
    ModelCallResult,
    ModelRequest,
    ModelUsage,
    ProviderKind,
    ProviderProfile,
    RepositoryTool,
)
from securecode_ai.contracts.base import ClosedModel
from securecode_ai.core.evidence_package import EvidencePackage, EvidencePackageLimits
from securecode_ai.core.investigation import AuditorInvestigationReceipt, InvestigationBudget
from securecode_ai.core.model_discovery import ModelDiscoveryReceipt
from securecode_ai.core.tool_policy import RepositoryToolReceipt, RepositoryToolRequest

from .config import ProviderProfileRegistry, parse_provider_profile
from .native_repository_tools import NATIVE_REPOSITORY_TOOLS_JSON

_SHA: Final = re.compile(r"[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class LocalProviderAdmissionError(ValueError):
    def __init__(self) -> None:
        super().__init__("local provider admission rejected")


def _reject() -> NoReturn:
    raise LocalProviderAdmissionError()


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


class EvidenceOrigin(StrEnum):
    LIVE = "LIVE"
    SIMULATED = "SIMULATED"
    FAULT_INJECTED = "FAULT_INJECTED"


class CapabilityCase(StrEnum):
    STRUCTURED_DISCOVERY = "structured_discovery"
    STRUCTURED_AUDITOR = "structured_auditor"
    NATIVE_REFUSAL = "native_refusal"
    NATIVE_INCOMPLETE = "native_incomplete"


class CoreCase(StrEnum):
    PYTHON_VULNERABLE = "python_vulnerable"
    PYTHON_SAFE = "python_safe"
    PYTHON_INTERFILE = "python_interfile"
    PYTHON_SAFE_INTERFILE = "python_safe_interfile"
    JAVASCRIPT_VULNERABLE = "javascript_vulnerable"
    JAVASCRIPT_SAFE = "javascript_safe"
    JAVASCRIPT_INTERFILE = "javascript_interfile"
    JAVASCRIPT_SAFE_INTERFILE = "javascript_safe_interfile"
    TYPESCRIPT_VULNERABLE = "typescript_vulnerable"
    TYPESCRIPT_SAFE = "typescript_safe"
    TYPESCRIPT_INTERFILE = "typescript_interfile"
    TYPESCRIPT_SAFE_INTERFILE = "typescript_safe_interfile"
    GO_VULNERABLE = "go_vulnerable"
    GO_SAFE = "go_safe"
    GO_INTERFILE = "go_interfile"
    GO_SAFE_INTERFILE = "go_safe_interfile"
    ZERO_SCANNER_NATIVE_FINDING = "zero_scanner_native_finding"
    NATIVE_COMPLETED_ZERO = "native_completed_zero"
    AUDITOR_ALL_CANDIDATES = "auditor_all_candidates"
    PROVIDER_FAULT = "provider_fault"
    TOOL_FAULT = "tool_fault"
    NATIVE_CYCLE = "native_cycle"


class AdmissionBindings(ClosedModel):
    """Host-reviewed pins outside the normative ProviderProfile."""

    provider_profile_sha256: str
    endpoint_sha256: str
    model_id: str
    model_manifest_sha256: str
    ollama_version: str
    ollama_artifact_sha256: str
    gateway_policy_sha256: str
    gateway_source_sha256: str
    connector_sha256: str
    native_tool_schema_sha256: str
    discovery_prompt_sha256: str
    discovery_schema_sha256: str
    auditor_prompt_sha256: str
    auditor_schema_sha256: str
    capabilities_sha256: str
    budgets_sha256: str

    @field_validator("*")
    @classmethod
    def _validate_pin(cls, value: str, info: object) -> str:
        name = getattr(info, "field_name", "")
        if name.endswith("_sha256") and _SHA.fullmatch(value) is None:
            _reject()
        if name == "model_id" and not 1 <= len(value) <= 128:
            _reject()
        if (
            name == "ollama_version"
            and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value)
            is None
        ):
            _reject()
        return value


class HostAdmissionPins(ClosedModel):
    bindings: AdmissionBindings
    approved_bundle_sha256: str
    review_receipt: ComponentPin
    producer_id: str
    independent_reviewer_id: str

    @field_validator("approved_bundle_sha256")
    @classmethod
    def _hash(cls, value: str) -> str:
        if _SHA.fullmatch(value) is None:
            _reject()
        return value

    @field_validator("producer_id", "independent_reviewer_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if _ID.fullmatch(value) is None:
            _reject()
        return value


class CapabilityEvidence(ClosedModel):
    case: CapabilityCase
    origin: EvidenceOrigin
    receipt_sha256: str
    request: ModelRequest
    result: ModelCallResult


class NativeToolEvidence(ClosedModel):
    origin: EvidenceOrigin
    receipt_sha256: str
    sent_prompt_sha256: str
    call_id: str
    model_request: ModelRequest
    request: RepositoryToolRequest
    receipt: RepositoryToolReceipt
    usage: ModelUsage


class AuditorInvocationEvidence(ClosedModel):
    """One actual candidate context and its request/usage, not runner attestation."""

    request: ModelRequest
    package: EvidencePackage
    selection_limits: EvidencePackageLimits
    usage: ModelUsage


class AuditorCandidateEvidence(ClosedModel):
    """The frozen Core loop budget and independently recorded attempt bindings."""

    budget: InvestigationBudget
    invocations: tuple[AuditorInvocationEvidence, ...] = Field(min_length=1, max_length=64)


class CoreConformanceEvidence(ClosedModel):
    case: CoreCase
    origin: EvidenceOrigin
    receipt_sha256: str
    recipe: ComponentPin
    request: ModelRequest
    discovery: ModelDiscoveryReceipt
    normalized_candidate_ids: tuple[str, ...] = Field(max_length=4096)
    scanner_candidate_ids: tuple[str, ...] = Field(max_length=4096)
    native_candidates: tuple[DiscoveryCandidate, ...] = Field(max_length=4096)
    scanner_candidates: tuple[DiscoveryCandidate, ...] = Field(max_length=4096)
    normalized_candidates: tuple[DiscoveryCandidate, ...] = Field(max_length=4096)
    auditors: tuple[AuditorInvestigationReceipt, ...] = Field(max_length=4096)
    auditor_invocations: tuple[AuditorCandidateEvidence, ...] = Field(max_length=4096)
    tool_receipts: tuple[RepositoryToolReceipt, ...] = Field(default=(), max_length=64)
    native_turn_request_hashes: tuple[str, ...] = Field(default=(), max_length=16)


def evidence_receipt_sha256(
    evidence: CapabilityEvidence | NativeToolEvidence | CoreConformanceEvidence,
) -> str:
    """Canonical content digest; a hash is not a LIVE origin or review authority."""

    domains = {
        CapabilityEvidence: "securecode.local-admission.capability.v1",
        NativeToolEvidence: "securecode.local-admission.native-tool.v1",
        CoreConformanceEvidence: "securecode.local-admission.core-conformance.v1",
    }
    domain = domains.get(type(evidence))
    if domain is None:
        _reject()
    return _digest(
        {
            "domain": domain,
            "record": evidence.model_dump(mode="json", exclude={"receipt_sha256"}),
        }
    )


def auditor_selection_sha256(package: EvidencePackage, limits: EvidencePackageLimits) -> str:
    """Recompute the existing Core evidence_package._selection_sha256 payload.

    This checks imported metadata without constructing a graph or running source.
    The reviewed bundle still owns provenance for the graph and producer pins.
    """

    return _digest(
        {
            "candidate_id": package.candidate_id,
            "candidate_version": package.candidate_version,
            "graph_id": package.graph_id,
            "graph_sha256": package.graph_sha256,
            "head_sha": package.head_sha,
            "limits": asdict(limits),
            "omitted_evidence_ids": list(package.omitted_evidence_ids),
            "selected": [asdict(item) for item in package.selected],
            "tenant_id": package.tenant_id,
        }
    )


class LocalProviderEvidenceBundle(ClosedModel):
    bindings: AdmissionBindings
    review_receipt: ComponentPin
    producer_id: str
    independent_reviewer_id: str
    capabilities: tuple[CapabilityEvidence, ...] = Field(max_length=4)
    native_tools: tuple[NativeToolEvidence, ...] = Field(max_length=4)
    core_cases: tuple[CoreConformanceEvidence, ...] = Field(max_length=len(CoreCase))

    @property
    def content_sha256(self) -> str:
        return _digest(self.model_dump(mode="json"))


class ReviewedLocalProviderEvidence:
    """Issuer-instance seal; no public constructor, serializer or receipt importer."""

    __slots__ = ("_bundle_bytes", "_owner", "_seal")
    _bundle_bytes: bytes
    _owner: TrustedLocalProviderAdmission
    _seal: object

    def __new__(cls) -> Self:
        raise TypeError("reviewed evidence is issued only by the trusted host authority")

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("reviewed evidence is immutable")

    def __repr__(self) -> str:
        return "ReviewedLocalProviderEvidence(<sealed>)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("reviewed evidence cannot be serialized")


class TrustedLocalProviderAdmission:
    """Construction is a host trust input, never analyzed-repository configuration."""

    __slots__ = ("_pins_bytes", "_profile_bytes", "_seal")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("host admission authority is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, *, approved_profile: bytes, pins: HostAdmissionPins):
        try:
            if type(approved_profile) is not bytes or type(pins) is not HostAdmissionPins:
                _reject()
            profile = parse_provider_profile(approved_profile)
            frozen = HostAdmissionPins.model_validate_json(pins.model_dump_json())
            binding = frozen.bindings
            if (
                frozen.producer_id == frozen.independent_reviewer_id
                or profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_LOCAL
                or profile.api_dialect is not ApiDialect.OPENAI_COMPATIBLE
                or profile.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
                or profile.credential_ref is not None
                or profile.canonical_content_hash() != binding.provider_profile_sha256
                or _digest(profile.endpoint.model_dump(mode="json")) != binding.endpoint_sha256
                or profile.model_id != binding.model_id
                or profile.model_snapshot != binding.model_manifest_sha256
                or _digest(profile.capabilities.model_dump(mode="json"))
                != binding.capabilities_sha256
                or _digest(profile.budgets.model_dump(mode="json")) != binding.budgets_sha256
                or hashlib.sha256(NATIVE_REPOSITORY_TOOLS_JSON).hexdigest()
                != binding.native_tool_schema_sha256
                or not all(
                    (
                        profile.capabilities.structured_output,
                        profile.capabilities.native_refusal_signal,
                        profile.capabilities.native_incomplete_signal,
                        profile.capabilities.tool_calling,
                        profile.capabilities.source_code_analysis,
                        profile.capabilities.repository_tool_calls,
                    )
                )
                or set(profile.capabilities.repository_tools) != set(RepositoryTool)
            ):
                _reject()
            self._profile_bytes = profile.model_dump_json().encode()
            self._pins_bytes = frozen.model_dump_json().encode()
            self._seal = object()
        except Exception:
            raise LocalProviderAdmissionError() from None

    def review(self, bundle: LocalProviderEvidenceBundle) -> ReviewedLocalProviderEvidence:
        from .local_provider_admission_validation import _validate_bundle

        try:
            if type(bundle) is not LocalProviderEvidenceBundle:
                _reject()
            frozen = LocalProviderEvidenceBundle.model_validate_json(bundle.model_dump_json())
            pins = HostAdmissionPins.model_validate_json(self._pins_bytes)
            if (
                frozen.content_sha256 != pins.approved_bundle_sha256
                or frozen.bindings != pins.bindings
                or frozen.review_receipt != pins.review_receipt
                or frozen.producer_id != pins.producer_id
                or frozen.independent_reviewer_id != pins.independent_reviewer_id
            ):
                _reject()
            profile = ProviderProfile.model_validate_json(self._profile_bytes)
            _validate_bundle(frozen, profile)
            reviewed = object.__new__(ReviewedLocalProviderEvidence)
            object.__setattr__(reviewed, "_owner", self)
            object.__setattr__(reviewed, "_seal", self._seal)
            object.__setattr__(reviewed, "_bundle_bytes", frozen.model_dump_json().encode())
            return reviewed
        except Exception:
            raise LocalProviderAdmissionError() from None

    def admit(self, reviewed: ReviewedLocalProviderEvidence) -> ProviderProfileRegistry:
        try:
            if (
                type(reviewed) is not ReviewedLocalProviderEvidence
                or reviewed._owner is not self
                or reviewed._seal is not self._seal
            ):
                _reject()
            # Revalidate canonical bytes and every receipt rather than trusting a
            # mutable object retained by an importer or the caller.
            self.review(LocalProviderEvidenceBundle.model_validate_json(reviewed._bundle_bytes))
            return ProviderProfileRegistry(
                (ProviderProfile.model_validate_json(self._profile_bytes),)
            )
        except Exception:
            raise LocalProviderAdmissionError() from None
