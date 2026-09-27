"""Public synthetic-Core composition through the existing authorization boundary.

This module composes the existing Core ports. Without an injected transport,
run_public_core_case can invoke the configured local provider. An injected
transport remains SIMULATED; this module never qualifies or admits a provider.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
from dataclasses import dataclass, field, replace
from typing import Final, NoReturn
from urllib.parse import urlsplit

from securecode_ai.adapters.config import parse_provider_profile
from securecode_ai.adapters.local_provider_admission import AuditorCandidateEvidence
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCompositionFailure,
)
from securecode_ai.adapters.public_core_fixtures import (
    PublicCoreFixture,
)
from securecode_ai.adapters.public_discovery_observation import (
    PublicDiscoveryObservationEvidence,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    EgressPolicyDocument,
    ExecutionBoundary,
    ModelPreflightResult,
    ModelRequest,
    ModelRole,
    ProviderKind,
    ProviderProfile,
)

from .local_provider_admission import CoreCase, EvidenceOrigin

_PUBLIC_CONTENT_KEY: Final = b"synthetic-public-core-fixture-content-key-v1" * 2
_ARTIFACT_FIELDS: Final = (
    "stage_catalogue",
    "workflow",
    "policy",
    "configuration",
    "tool_policy",
    "repository_scope",
    "repository_view_policy",
    "producer",
)
_MAX_ARTIFACT_BYTES: Final = 128 * 1024
_MAX_ARTIFACT_DOCUMENT_BYTES: Final = 1024 * 1024
_RULE_IDS: Final = frozenset({"cwe-89-sql-interpolation"})
_DIAGNOSTIC_CONFIGURATION_SCHEMA: Final = "securecode.public-core-diagnostic-sampling.v1"
_LLAMA31_DIAGNOSTIC_MODEL_ID: Final = "llama3.1:8b-instruct-q3_K_M"
_PIN_FIELDS: Final = frozenset(
    {"schema_version", "extensions", "component_id", "component_version", "content_sha256"}
)


class PublicCoreRunnerError(ValueError):
    """Fixed non-echoing public composition error."""

    def __init__(self) -> None:
        super().__init__("public Core composition failed")
        self.__cause__ = None
        self.__context__ = None


def _fail() -> NoReturn:
    raise PublicCoreRunnerError()


def _pin(component_id: str, content: bytes) -> ComponentPin:
    if type(content) is not bytes or not content or len(content) > _MAX_ARTIFACT_BYTES:
        _fail()
    try:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version="1.0.0",
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
    except ValueError:
        _fail()


@dataclass(frozen=True, slots=True)
class PublicCoreDiagnosticSampling:
    """Closed opt-in sampling for the exact native Discovery diagnostic."""

    provider_profile: ComponentPin
    model_id: str
    model_snapshot: str
    temperature: float
    seed: int


def _closed_component_pin(value: object) -> ComponentPin:
    if type(value) is not dict or set(value) != _PIN_FIELDS:
        _fail()
    try:
        return ComponentPin.model_validate_json(
            json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        )
    except ValueError:
        _fail()


def _diagnostic_sampling(
    configuration: bytes, profile: ProviderProfile, provider_pin: ComponentPin
) -> PublicCoreDiagnosticSampling | None:
    """Decode the versioned opt-in envelope from retained configuration bytes.

    Legacy opaque configuration artifacts remain ordinary configuration.  Any
    artifact that declares this diagnostic schema is closed and must validate
    completely before fixture context or connector construction.
    """
    if type(configuration) is not bytes or not configuration:
        _fail()
    try:
        document = json.loads(configuration.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeError, json.JSONDecodeError):
        if _DIAGNOSTIC_CONFIGURATION_SCHEMA.encode("ascii") in configuration:
            _fail()
        return None
    if (
        type(document) is not dict
        or document.get("schema_version") != _DIAGNOSTIC_CONFIGURATION_SCHEMA
    ):
        return None
    if (
        set(document) != {"schema_version", "diagnostic"}
        or type(document["diagnostic"]) is not dict
    ):
        _fail()
    diagnostic = document["diagnostic"]
    if set(diagnostic) != {
        "provider_profile",
        "model_id",
        "model_snapshot",
        "role",
        "native",
        "sampling",
    }:
        _fail()
    sampling = diagnostic["sampling"]
    if type(sampling) is not dict or set(sampling) != {"temperature", "seed"}:
        _fail()
    provider = _closed_component_pin(diagnostic["provider_profile"])
    model_id = diagnostic["model_id"]
    snapshot = diagnostic["model_snapshot"]
    temperature = sampling["temperature"]
    seed = sampling["seed"]
    if (
        provider != provider_pin
        or type(model_id) is not str
        or model_id != _LLAMA31_DIAGNOSTIC_MODEL_ID
        or profile.model_id != model_id
        or type(snapshot) is not str
        or len(snapshot) != 64
        or any(char not in "0123456789abcdef" for char in snapshot)
        or profile.model_snapshot != snapshot
        or diagnostic["role"] != ModelRole.DISCOVERY.name
        or diagnostic["native"] is not True
        or type(temperature) not in {int, float}
        or isinstance(temperature, bool)
        or float(temperature) != 0.0
        or type(seed) is not int
        or isinstance(seed, bool)
        or seed != 7
    ):
        _fail()
    return PublicCoreDiagnosticSampling(provider, model_id, snapshot, 0.0, seed)


def _closed_object(pairs: list[tuple[object, object]]) -> dict[object, object]:
    result: dict[object, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in result:
            _fail()
        result[key] = item
    return result


def _decode_artifacts(value: bytes) -> dict[str, bytes]:
    if type(value) is not bytes or not value or len(value) > _MAX_ARTIFACT_DOCUMENT_BYTES:
        _fail()
    try:
        document = json.loads(value.decode("utf-8"), object_pairs_hook=_closed_object)
        if type(document) is not dict or set(document) != set(_ARTIFACT_FIELDS):
            _fail()
        decoded: dict[str, bytes] = {}
        for name in _ARTIFACT_FIELDS:
            encoded = document[name]
            if type(encoded) is not str:
                _fail()
            decoded[name] = base64.b64decode(encoded.encode("ascii"), validate=True)
        return decoded
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        _fail()


@dataclass(frozen=True, slots=True)
class PublicCoreArtifactPins:
    """Pins derived from the exact host-reviewed bytes used for one public run."""

    stage_catalogue: ComponentPin
    workflow: ComponentPin
    policy: ComponentPin
    configuration: ComponentPin
    tool_policy: ComponentPin
    repository_scope: ComponentPin
    repository_view_policy: ComponentPin
    producer: ComponentPin

    @classmethod
    def from_bytes(
        cls,
        *,
        stage_catalogue: bytes,
        workflow: bytes,
        policy: bytes,
        configuration: bytes,
        tool_policy: bytes,
        repository_scope: bytes,
        repository_view_policy: bytes,
        producer: bytes,
    ) -> PublicCoreArtifactPins:
        values = {
            "stage_catalogue": stage_catalogue,
            "workflow": workflow,
            "policy": policy,
            "configuration": configuration,
            "tool_policy": tool_policy,
            "repository_scope": repository_scope,
            "repository_view_policy": repository_view_policy,
            "producer": producer,
        }
        if set(values) != set(_ARTIFACT_FIELDS):
            _fail()
        return cls(
            **{
                name: _pin(f"public-core-{name.replace('_', '-')}", value)
                for name, value in values.items()
            }
        )


@dataclass(frozen=True, slots=True)
class PublicCoreHostInputs:
    """Deep-validated host configuration with no capability override path."""

    profile: ProviderProfile
    policy: EgressPolicyDocument
    artifacts: PublicCoreArtifactPins
    diagnostic_sampling: PublicCoreDiagnosticSampling | None
    gateway_port: int
    _profile_bytes: bytes = field(repr=False)
    _policy_bytes: bytes = field(repr=False)
    _configuration_bytes: bytes = field(repr=False)
    _artifacts_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.profile) is not ProviderProfile
            or type(self.policy) is not EgressPolicyDocument
            or type(self.artifacts) is not PublicCoreArtifactPins
            or (
                self.diagnostic_sampling is not None
                and type(self.diagnostic_sampling) is not PublicCoreDiagnosticSampling
            )
            or type(self.gateway_port) is not int
            or isinstance(self.gateway_port, bool)
            or not 1 <= self.gateway_port <= 65535
            or type(self._profile_bytes) is not bytes
            or type(self._policy_bytes) is not bytes
            or type(self._configuration_bytes) is not bytes
            or type(self._artifacts_bytes) is not bytes
        ):
            _fail()
        try:
            profile = parse_provider_profile(self._profile_bytes)
            policy = EgressPolicyDocument.model_validate_json(self._policy_bytes)
            decoded = _decode_artifacts(self._artifacts_bytes)
            artifacts = PublicCoreArtifactPins.from_bytes(**decoded)
            policy_pin = ComponentPin(
                schema_version=CONTRACT_SCHEMA_VERSION,
                component_id=policy.policy_id,
                component_version=policy.policy_version,
                content_sha256=policy.canonical_content_hash(),
            )
            artifacts = replace(artifacts, policy=policy_pin)
            provider_pin = ComponentPin(
                schema_version=CONTRACT_SCHEMA_VERSION,
                component_id=profile.profile_id,
                component_version=profile.profile_version,
                content_sha256=profile.canonical_content_hash(),
            )
            diagnostic_sampling = _diagnostic_sampling(
                self._configuration_bytes, profile, provider_pin
            )
            if (
                profile.canonical_content_hash() != self.profile.canonical_content_hash()
                or policy.canonical_content_hash() != self.policy.canonical_content_hash()
                or self.artifacts != artifacts
                or self._configuration_bytes != decoded["configuration"]
                or self.diagnostic_sampling != diagnostic_sampling
            ):
                _fail()
            endpoint = urlsplit(profile.endpoint.base_url)
            local = (
                profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_LOCAL
                and profile.execution_boundary is ExecutionBoundary.LOCAL_RUNNER
                and profile.credential_ref is None
                and endpoint.hostname == "127.0.0.1"
                and (endpoint.port or 80) == self.gateway_port
                and profile.endpoint.authority == "127.0.0.1"
            )
            remote = (
                profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_REMOTE
                and profile.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
                and profile.credential_ref is not None
                and type(profile.protocol_framing_token_upper_bound) is int
                and endpoint.scheme == "https"
                and (endpoint.port or 443) == self.gateway_port
                and self.diagnostic_sampling is None
            )
            if (
                not (local or remote)
                or artifacts.policy != policy_pin
                or artifacts.configuration
                != _pin("public-core-configuration", self._configuration_bytes)
            ):
                _fail()
            object.__setattr__(self, "profile", profile)
            object.__setattr__(self, "policy", policy)
            object.__setattr__(self, "artifacts", artifacts)
            object.__setattr__(self, "diagnostic_sampling", diagnostic_sampling)
            object.__setattr__(self, "_profile_bytes", bytes(self._profile_bytes))
            object.__setattr__(self, "_policy_bytes", bytes(self._policy_bytes))
            object.__setattr__(self, "_configuration_bytes", bytes(self._configuration_bytes))
            object.__setattr__(self, "_artifacts_bytes", bytes(self._artifacts_bytes))
        except (TypeError, ValueError):
            _fail()

    def snapshot(self) -> PublicCoreHostInputs:
        """Revalidate and detach every mutable nested input before public work."""
        return PublicCoreHostInputs(
            profile=self.profile,
            policy=self.policy,
            artifacts=self.artifacts,
            diagnostic_sampling=self.diagnostic_sampling,
            gateway_port=self.gateway_port,
            _profile_bytes=self._profile_bytes,
            _policy_bytes=self._policy_bytes,
            _configuration_bytes=self._configuration_bytes,
            _artifacts_bytes=self._artifacts_bytes,
        )

    @property
    def provider_pin(self) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=self.profile.profile_id,
            component_version=self.profile.profile_version,
            content_sha256=self.profile.canonical_content_hash(),
        )

    @property
    def capability_pin(self) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=f"{self.profile.profile_id}-capabilities",
            component_version=self.profile.profile_version,
            content_sha256=hashlib.sha256(
                json.dumps(
                    self.profile.capabilities.model_dump(mode="json"),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )

    @property
    def policy_pin(self) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=self.policy.policy_id,
            component_version=self.policy.policy_version,
            content_sha256=self.policy.canonical_content_hash(),
        )

    @property
    def egress_pin(self) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=self.policy.profile.value,
            component_version=self.policy.policy_version,
            content_sha256=self.policy.canonical_content_hash(),
        )


class PinnedLiteralLoopbackResolver:
    """A DNS-free resolver that permits precisely one pinned loopback socket."""

    __slots__ = ("_authority", "_port")

    def __init__(self, *, authority: str = "127.0.0.1", port: int = 11435) -> None:
        if (
            type(authority) is not str
            or authority != "127.0.0.1"
            or type(port) is not int
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            _fail()
        self._authority = authority
        self._port = port

    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        if type(authority) is not str or type(port) is not int or isinstance(port, bool):
            _fail()
        if authority != self._authority or port != self._port:
            _fail()
        return (self._authority,)


class SystemPublicResolver:
    """Resolve a public provider authority only when the endpoint issuer asks."""

    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        if (
            type(authority) is not str
            or not authority
            or type(port) is not int
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            _fail()
        try:
            addresses = tuple(
                sorted(
                    {
                        item[4][0]
                        for item in socket.getaddrinfo(authority, port, type=socket.SOCK_STREAM)
                        if isinstance(item[4][0], str)
                    }
                )
            )
        except OSError:
            _fail()
        if not addresses:
            _fail()
        return addresses


@dataclass(frozen=True, slots=True)
class PreparedPublicCoreCase:
    case: CoreCase
    request: ModelRequest
    fixture: PublicCoreFixture = field(repr=False)
    preflight: ModelPreflightResult


@dataclass(frozen=True, slots=True)
class PublicCoreRunResult:
    """Source-free diagnostic output; it cannot attest provider admission."""

    case: CoreCase
    origin: EvidenceOrigin | None
    preflight: ModelPreflightResult
    flow: ProductCandidateFlow | ProductCompositionFailure | None = field(repr=False)
    auditor_evidence: tuple[AuditorCandidateEvidence, ...] = field(default=(), repr=False)
    failure_code: str | None = None
    discovery_observation: PublicDiscoveryObservationEvidence | None = field(
        default=None, repr=False
    )

    @property
    def production_admitted(self) -> bool:
        return False

    @property
    def flow_constructed(self) -> bool:
        return type(self.flow) is ProductCandidateFlow

    @property
    def completed(self) -> bool:
        if type(self.flow) is not ProductCandidateFlow or self.failure_code is not None:
            return False
        return (
            not self.flow.deterministic_failed
            and self.flow.discovery.required_terminal_outcome is None
            and all(not receipt.is_indeterminate for receipt in self.flow.investigations)
        )
