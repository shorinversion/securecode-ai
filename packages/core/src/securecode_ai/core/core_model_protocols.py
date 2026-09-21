"""Framework-independent model and egress policy boundary behavior."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    DataClass,
    EgressManifest,
    EgressPolicyDocument,
    ModelCallResult,
    ModelPreflightRequest,
    ModelRequest,
    ProviderProfile,
    RepositoryTool,
)

if TYPE_CHECKING:
    from .core_model_authorizations import PreContextAuthorization, PreSendAuthorization
    from .core_model_issuer import ModelAuthorizationIssuer

_CLASS_RANK: Final = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL_METADATA: 1,
    DataClass.CONFIDENTIAL_SECURITY: 2,
    DataClass.CONFIDENTIAL_SOURCE: 3,
    DataClass.RESTRICTED: 4,
}
_REPOSITORY_TOOLS: Final = frozenset(RepositoryTool)
_PERMIT_SENTINEL: Final = object()


class ApprovedProviderRegistry(Protocol):
    def require_registered(self, supplied: ProviderProfile) -> ProviderProfile: ...


@dataclass(frozen=True, slots=True)
class PayloadValidation:
    accepted: bool
    error_code: str | None
    content_id: str | None
    data_class: DataClass | None
    validator: ComponentPin


class StructuredPayloadValidator(Protocol):
    @property
    def validator(self) -> ComponentPin: ...

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation: ...


class EphemeralModelPayload(Protocol):
    def reveal_for(self, request_id: str) -> object: ...

    def close(self) -> None: ...


class ModelProviderResult(Protocol):
    @property
    def result(self) -> ModelCallResult: ...

    @property
    def payload(self) -> EphemeralModelPayload | None: ...


class ModelProvider(Protocol):
    """One provider attempt; retries and workflow routing remain external."""

    def invoke(
        self,
        *,
        request: ModelRequest,
        authorization: PreSendAuthorization,
        model_issuer: ModelAuthorizationIssuer,
        validator: StructuredPayloadValidator,
    ) -> ModelProviderResult: ...


class EgressPolicyEvaluator(Protocol):
    def authorize_pre_context(
        self,
        preflight: ModelPreflightRequest,
        *,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
    ) -> PreContextAuthorization: ...

    def authorize_pre_send(
        self,
        pre_context: PreContextAuthorization,
        manifest: EgressManifest,
    ) -> PreSendAuthorization: ...


class AuthorizationError(ValueError):
    """Safe authorization failure with a bounded code and no untrusted data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EgressPolicyRegistry:
    """Immutable policy registry backed by canonical bytes, never live model objects."""

    __slots__ = ("_hashes", "_policies")

    _IMMUTABLE_FIELDS: Final = frozenset({"_hashes", "_policies"})

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._IMMUTABLE_FIELDS and hasattr(self, name):
            raise AttributeError("egress policy registry storage is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, policies: Iterable[EgressPolicyDocument]) -> None:
        encoded: dict[str, bytes] = {}
        hashes: dict[str, str] = {}
        for supplied in policies:
            try:
                policy = EgressPolicyDocument.model_validate_json(supplied.canonical_bytes())
            except (AttributeError, TypeError, ValueError):
                raise AuthorizationError("INVALID_EGRESS_POLICY") from None
            selector = policy.selector
            content_hash = policy.canonical_content_hash()
            if selector in hashes and hashes[selector] != content_hash:
                raise AuthorizationError("IMMUTABLE_EGRESS_POLICY_CONFLICT")
            encoded[selector] = policy.canonical_bytes()
            hashes[selector] = content_hash
        self._policies = MappingProxyType(encoded)
        self._hashes = MappingProxyType(hashes)

    def select(self, selector: str) -> EgressPolicyDocument:
        try:
            encoded = self._policies[selector]
            expected_hash = self._hashes[selector]
        except (KeyError, TypeError):
            raise AuthorizationError("UNKNOWN_EGRESS_POLICY") from None
        try:
            policy = EgressPolicyDocument.model_validate_json(encoded)
        except ValueError:
            raise AuthorizationError("EGRESS_POLICY_INTEGRITY_FAILURE") from None
        if policy.canonical_content_hash() != expected_hash:
            raise AuthorizationError("EGRESS_POLICY_INTEGRITY_FAILURE")
        return policy

    def require_registered(self, supplied: EgressPolicyDocument) -> EgressPolicyDocument:
        try:
            candidate = EgressPolicyDocument.model_validate_json(supplied.canonical_bytes())
            approved = self.select(candidate.selector)
        except (AttributeError, TypeError, ValueError):
            raise AuthorizationError("INVALID_EGRESS_POLICY") from None
        if candidate.canonical_content_hash() != approved.canonical_content_hash():
            raise AuthorizationError("IMMUTABLE_EGRESS_POLICY_CONFLICT")
        return approved


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_model_request_hash(request: ModelRequest) -> str:
    """Return the stable full semantic identity of a revalidated model request."""

    validated = ModelRequest.model_validate_json(request.model_dump_json())
    return _canonical_hash(validated.model_dump(mode="json"))


def _component_pin(identifier: str, version: str, content_hash: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=identifier,
        component_version=version,
        content_sha256=content_hash,
    )
