"""Immutable provider-profile configuration contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from enum import StrEnum
from typing import Annotated, Any, Final, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from .base import DataClass, SemVer

_REMOTE_PROVIDER_KINDS: Final = frozenset({"openai", "anthropic", "openai_compatible_remote"})
_CONSUMER_ENDPOINT_SUFFIXES: Final = (
    "aistudio.google.com",
    "chatgpt.com",
    "chat.openai.com",
    "claude.ai",
    "console.anthropic.com",
    "copilot.github.com",
    "gemini.google.com",
    "copilot.microsoft.com",
    "platform.openai.com",
)
_REPOSITORY_TOOLS: Final = frozenset({"list_paths", "lookup_symbol", "read_range", "read_evidence"})
_ENV_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class ProviderConfigModel(BaseModel):
    """Closed immutable model for the separately versioned provider profile."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


class ProviderKind(StrEnum):
    FAKE = "fake"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENAI_COMPATIBLE_LOCAL = "openai_compatible_local"
    OPENAI_COMPATIBLE_REMOTE = "openai_compatible_remote"


class ApiDialect(StrEnum):
    FAKE = "fake"
    OPENAI_RESPONSES = "openai_responses"
    ANTHROPIC_MESSAGES = "anthropic_messages"
    OPENAI_COMPATIBLE = "openai_compatible"


class ExecutionBoundary(StrEnum):
    LOCAL_RUNNER = "local_runner"
    PRIVATE_TENANT_ENDPOINT = "private_tenant_endpoint"
    PUBLIC_EXTERNAL = "public_external"


class RepositoryTool(StrEnum):
    LIST_PATHS = "list_paths"
    LOOKUP_SYMBOL = "lookup_symbol"
    READ_RANGE = "read_range"
    READ_EVIDENCE = "read_evidence"


class ProviderEvidenceStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    NOT_APPLICABLE_LOCAL = "not_applicable_local"


class ProviderTrainingUse(StrEnum):
    NONE_VERIFIED = "none_verified"
    PROVIDER_DECLARED = "provider_declared"
    UNKNOWN = "unknown"
    NOT_APPLICABLE_LOCAL = "not_applicable_local"


class ModelPurpose(StrEnum):
    MODEL_NATIVE_DISCOVERY = "model_native_discovery"
    CANDIDATE_INVESTIGATION = "candidate_investigation"
    SKEPTIC_REVIEW = "skeptic_review"
    PATCH_GENERATION = "patch_generation"
    EVALUATION = "evaluation"


class EgressProfileId(StrEnum):
    AIR_GAP = "air_gap"
    NO_CODE_EGRESS = "no_code_egress"
    PRIVATE_MODEL_ZDR = "private_model_zdr"
    METADATA_EXTERNAL = "metadata_external"
    MANAGED_SCAN_OPT_IN = "managed_scan_opt_in"


PositiveInt = Annotated[int, Field(strict=True, ge=1)]
TokenUpperBound = Annotated[int, Field(strict=True, ge=1, le=1_000_000_000)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
CredentialRef = Annotated[
    str,
    Field(pattern=r"^(env|secret|workload)://[A-Za-z0-9._/-]+$", max_length=256),
]
ProviderProfileId = Annotated[
    str,
    Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$", max_length=64),
]


def _sorted_unique(values: list[Any]) -> tuple[Any, ...]:
    if len(values) != len(set(values)):
        raise ValueError("set-like provider fields must contain unique values")
    return tuple(sorted(values, key=str))


class ProviderEndpoint(ProviderConfigModel):
    base_url: Annotated[str, Field(min_length=1, max_length=2048)]
    authority: Annotated[str, Field(min_length=1, max_length=253)]
    allowed_ports: tuple[Port, ...] = Field(min_length=1, max_length=32)
    follow_redirects: StrictBool
    local_plaintext_exception: StrictBool

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def _canonicalize_ports(cls, value: object) -> object:
        return _sorted_unique(list(value)) if isinstance(value, (list, tuple)) else value

    @model_validator(mode="after")
    def _validate_url_shape(self) -> Self:
        try:
            parsed = urlsplit(self.base_url)
            port = parsed.port
        except ValueError as error:
            raise ValueError("provider endpoint URL is invalid") from error
        if (
            not parsed.scheme
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(char) < 32 or ord(char) == 127 for char in self.base_url)
        ):
            raise ValueError("provider endpoint forbids userinfo, query, fragment and controls")
        if self.follow_redirects:
            raise ValueError("provider endpoint redirects are forbidden")
        hostname = parsed.hostname.lower()
        if (
            self.authority != self.authority.lower()
            or self.authority.endswith(".")
            or not self.authority.isascii()
            or hostname != self.authority
        ):
            raise ValueError("provider endpoint authority must exactly match normalized URL host")
        effective_port = port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != "fake" and effective_port not in self.allowed_ports:
            raise ValueError("provider endpoint port is not in the profile allowlist")
        return self

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme.lower()


class ProviderCapabilities(ProviderConfigModel):
    structured_output: StrictBool
    native_refusal_signal: StrictBool
    native_incomplete_signal: StrictBool
    tool_calling: StrictBool
    source_code_analysis: StrictBool
    repository_tool_calls: StrictBool
    repository_tools: tuple[RepositoryTool, ...] = Field(max_length=4)
    max_context_tokens: PositiveInt
    max_output_tokens: PositiveInt

    @field_validator("repository_tools", mode="before")
    @classmethod
    def _canonicalize_tools(cls, value: object) -> object:
        return _sorted_unique(list(value)) if isinstance(value, (list, tuple)) else value

    @model_validator(mode="after")
    def _validate_repository_tools(self) -> Self:
        tools = {tool.value for tool in self.repository_tools}
        if self.repository_tool_calls:
            if not self.tool_calling or tools != _REPOSITORY_TOOLS:
                raise ValueError("repository tool calls require the complete bounded tool set")
        elif tools:
            raise ValueError("repository tools require repository_tool_calls")
        if self.max_output_tokens > self.max_context_tokens:
            raise ValueError("max_output_tokens cannot exceed max_context_tokens")
        return self


class ProviderDataTerms(ProviderConfigModel):
    evidence_status: ProviderEvidenceStatus
    residency: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = Field(
        max_length=64
    )
    retention_seconds: Annotated[int, Field(strict=True, ge=0)] | None
    training_use: ProviderTrainingUse
    zero_data_retention: StrictBool | None
    maximum_input_data_class: DataClass
    allowed_purposes: tuple[ModelPurpose, ...] = Field(min_length=1, max_length=5)
    evidence_ref: Annotated[str, Field(min_length=1, max_length=512)] | None = None

    @field_validator("residency", "allowed_purposes", mode="before")
    @classmethod
    def _canonicalize_sets(cls, value: object) -> object:
        return _sorted_unique(list(value)) if isinstance(value, (list, tuple)) else value

    @field_validator("maximum_input_data_class")
    @classmethod
    def _forbid_restricted_input(cls, value: DataClass) -> DataClass:
        if value is DataClass.RESTRICTED:
            raise ValueError("provider profiles cannot accept DC4_RESTRICTED")
        return value


class ProviderBudgets(ProviderConfigModel):
    timeout_seconds: PositiveInt
    max_attempts: Annotated[int, Field(strict=True, ge=1, le=10)]
    max_total_tokens: PositiveInt


class ProviderProfile(ProviderConfigModel):
    """Validated, secret-free provider execution profile from the frozen contract."""

    schema_version: Annotated[str, Field(pattern=r"^0\.2\.0$")]
    profile_id: ProviderProfileId
    profile_version: SemVer
    provider_kind: ProviderKind
    api_dialect: ApiDialect
    endpoint: ProviderEndpoint
    execution_boundary: ExecutionBoundary
    model_id: Annotated[str, Field(min_length=1, max_length=256)]
    model_snapshot: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    protocol_framing_token_upper_bound: TokenUpperBound | None = None
    capabilities: ProviderCapabilities
    data_terms: ProviderDataTerms
    credential_ref: CredentialRef | None
    egress_profiles: tuple[EgressProfileId, ...] = Field(min_length=1, max_length=5)
    budgets: ProviderBudgets

    @field_validator("egress_profiles", mode="before")
    @classmethod
    def _canonicalize_egress_profiles(cls, value: object) -> object:
        return _sorted_unique(list(value)) if isinstance(value, (list, tuple)) else value

    @field_validator("credential_ref")
    @classmethod
    def _validate_credential_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        scheme, _, name = value.partition("://")
        if scheme == "env":
            if not _ENV_NAME.fullmatch(name):
                raise ValueError("environment credential reference name is invalid")
        elif any(part in {"", ".", ".."} for part in name.split("/")):
            raise ValueError("credential backend reference path is invalid")
        return value

    @model_validator(mode="after")
    def _validate_provider_boundary(self) -> Self:
        expected_dialect = {
            ProviderKind.FAKE: ApiDialect.FAKE,
            ProviderKind.OPENAI: ApiDialect.OPENAI_RESPONSES,
            ProviderKind.ANTHROPIC: ApiDialect.ANTHROPIC_MESSAGES,
            ProviderKind.OPENAI_COMPATIBLE_LOCAL: ApiDialect.OPENAI_COMPATIBLE,
            ProviderKind.OPENAI_COMPATIBLE_REMOTE: ApiDialect.OPENAI_COMPATIBLE,
        }[self.provider_kind]
        if self.api_dialect is not expected_dialect:
            raise ValueError("provider kind and API dialect are incompatible")

        if self.provider_kind is ProviderKind.OPENAI_COMPATIBLE_REMOTE:
            if self.protocol_framing_token_upper_bound is None:
                raise ValueError("remote compatible providers require a protocol token bound")
        elif self.protocol_framing_token_upper_bound is not None:
            raise ValueError("protocol token bound is only valid for remote compatible providers")

        hostname = self.endpoint.authority
        consumer_host = any(
            hostname == suffix or hostname.endswith(f".{suffix}")
            for suffix in _CONSUMER_ENDPOINT_SUFFIXES
        )
        if consumer_host:
            raise ValueError("consumer chat/web products are not provider endpoints")

        parsed_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        try:
            parsed_ip = ipaddress.ip_address(hostname)
        except ValueError:
            parsed_ip = None

        if self.provider_kind.value in _REMOTE_PROVIDER_KINDS:
            if (
                not self.endpoint.base_url.startswith("https://")
                or self.endpoint.local_plaintext_exception
                or self.execution_boundary is ExecutionBoundary.LOCAL_RUNNER
                or self.credential_ref is None
            ):
                raise ValueError("remote providers require HTTPS, credentials and remote boundary")
            if parsed_ip is not None and not parsed_ip.is_global:
                raise ValueError("remote provider literal IP must be globally routable")
        elif self.provider_kind is ProviderKind.OPENAI_COMPATIBLE_LOCAL:
            if (
                self.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
                or parsed_ip is None
                or not parsed_ip.is_loopback
                or not self.endpoint.base_url.startswith(("http://", "https://"))
                or (self.endpoint.scheme == "http" and not self.endpoint.local_plaintext_exception)
            ):
                raise ValueError("local plaintext provider requires an exact loopback profile")
        elif (
            self.endpoint.scheme != "fake"
            or self.endpoint.authority != "local"
            or self.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
            or self.credential_ref is not None
        ):
            raise ValueError("fake provider must be local, credential-free and fake-scheme")
        return self

    @property
    def selector(self) -> str:
        return f"{self.profile_id}@{self.profile_version}"

    def canonical_content_hash(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


__all__ = [
    "ApiDialect",
    "CredentialRef",
    "EgressProfileId",
    "ExecutionBoundary",
    "ModelPurpose",
    "ProviderBudgets",
    "ProviderCapabilities",
    "ProviderConfigModel",
    "ProviderDataTerms",
    "ProviderEndpoint",
    "ProviderEvidenceStatus",
    "ProviderKind",
    "ProviderProfile",
    "ProviderProfileId",
    "ProviderTrainingUse",
    "RepositoryTool",
    "TokenUpperBound",
]
