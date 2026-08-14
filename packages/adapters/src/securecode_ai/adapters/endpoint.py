"""Connect-time endpoint authorization without opening sockets."""

from __future__ import annotations

import ipaddress
import secrets
from typing import Any, Final, Protocol, SupportsIndex
from urllib.parse import urlsplit

from securecode_ai.core import (
    AuthorizationError,
    ModelAuthorizationIssuer,
    PreSendAuthorization,
    ProviderKind,
    ProviderProfile,
)

from .config import ProviderProfileRegistry

_AUTHORIZATION_SENTINEL: Final = object()


class Resolver(Protocol):
    def resolve(self, authority: str, port: int) -> tuple[str, ...]: ...


class EndpointError(ValueError):
    """Safe endpoint failure that never includes an address supplied by DNS."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EndpointAuthorization:
    __slots__ = (
        "_addresses",
        "_attempt",
        "_authority",
        "_expires_at",
        "_issuer_id",
        "_manifest_hash",
        "_nonce",
        "_policy_hash",
        "_port",
        "_profile_hash",
        "_request_hash",
        "_scheme",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("endpoint authorizations are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        sentinel: object,
        issuer_id: str,
        nonce: str,
        request_hash: str,
        profile_hash: str,
        policy_hash: str,
        manifest_hash: str,
        attempt: int,
        scheme: str,
        authority: str,
        port: int,
        addresses: tuple[str, ...],
        expires_at: float,
    ) -> None:
        if sentinel is not _AUTHORIZATION_SENTINEL:
            raise TypeError("endpoint authorizations are issuer-owned")
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = request_hash
        self._profile_hash = profile_hash
        self._policy_hash = policy_hash
        self._manifest_hash = manifest_hash
        self._attempt = attempt
        self._scheme = scheme
        self._authority = authority
        self._port = port
        self._addresses = addresses
        self._expires_at = expires_at

    @property
    def authority(self) -> str:
        return self._authority

    @property
    def port(self) -> int:
        return self._port

    @property
    def connect_addresses(self) -> tuple[str, ...]:
        return self._addresses

    def __repr__(self) -> str:
        return "EndpointAuthorization(<opaque>)"

    def __copy__(self) -> EndpointAuthorization:
        raise TypeError("endpoint authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> EndpointAuthorization:
        del memo
        raise TypeError("endpoint authorizations cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("endpoint authorizations cannot be serialized")


class VerifiedEndpointAuthorization:
    __slots__ = (
        "_attempt",
        "_authority",
        "_issuer_id",
        "_manifest_hash",
        "_nonce",
        "_peer_ip",
        "_policy_hash",
        "_port",
        "_profile_hash",
        "_request_hash",
        "_scheme",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("verified endpoints are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        sentinel: object,
        issuer_id: str,
        nonce: str,
        endpoint: EndpointAuthorization,
        peer_ip: str,
    ) -> None:
        if sentinel is not _AUTHORIZATION_SENTINEL:
            raise TypeError("verified endpoints are issuer-owned")
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = endpoint._request_hash
        self._profile_hash = endpoint._profile_hash
        self._policy_hash = endpoint._policy_hash
        self._manifest_hash = endpoint._manifest_hash
        self._attempt = endpoint._attempt
        self._scheme = endpoint._scheme
        self._authority = endpoint._authority
        self._port = endpoint._port
        self._peer_ip = peer_ip

    def __repr__(self) -> str:
        return "VerifiedEndpointAuthorization(<opaque>)"

    def __copy__(self) -> VerifiedEndpointAuthorization:
        raise TypeError("verified endpoints cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> VerifiedEndpointAuthorization:
        del memo
        raise TypeError("verified endpoints cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("verified endpoints cannot be serialized")


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or "%" in value or len(value) > 64:
        raise EndpointError("ENDPOINT_ADDRESS_DENIED")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise EndpointError("ENDPOINT_ADDRESS_DENIED") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise EndpointError("ENDPOINT_ADDRESS_DENIED")
    return address


def _is_exact_local(profile: ProviderProfile) -> bool:
    return (
        profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_LOCAL
        and profile.endpoint.local_plaintext_exception
        and profile.execution_boundary.value == "local_runner"
    )


def _validate_address(profile: ProviderProfile, value: str) -> str:
    address = _ip(value)
    if _is_exact_local(profile):
        try:
            configured = _ip(profile.endpoint.authority)
        except EndpointError:
            raise EndpointError("LOCAL_ENDPOINT_LITERAL_REQUIRED") from None
        if not configured.is_loopback or address != configured:
            raise EndpointError("LOCAL_ENDPOINT_SCOPE_MISMATCH")
    elif not address.is_global:
        raise EndpointError("ENDPOINT_ADDRESS_DENIED")
    return address.compressed


def _resolve(profile: ProviderProfile, resolver: Resolver, port: int) -> tuple[str, ...]:
    authority = profile.endpoint.authority
    raw: tuple[str, ...]
    try:
        literal = _ip(authority)
    except EndpointError:
        literal = None
    if literal is not None:
        raw = (authority,)
    else:
        try:
            raw = resolver.resolve(authority, port)
        except Exception:
            raise EndpointError("ENDPOINT_RESOLUTION_FAILED") from None
    if not raw or len(raw) > 64:
        raise EndpointError("ENDPOINT_RESOLUTION_FAILED")
    addresses = tuple(sorted({_validate_address(profile, item) for item in raw}))
    if not addresses:
        raise EndpointError("ENDPOINT_RESOLUTION_FAILED")
    return addresses


class EndpointAuthorizationIssuer:
    """Issues single-attempt endpoint proofs before application data is attached."""

    __slots__ = (
        "_active_endpoints",
        "_active_verified",
        "_consumed_endpoints",
        "_consumed_verified",
        "_issuer_id",
        "_provider_registry",
    )

    def __init__(self, *, provider_registry: ProviderProfileRegistry) -> None:
        self._provider_registry = provider_registry
        self._issuer_id = secrets.token_hex(16)
        self._active_endpoints: dict[str, EndpointAuthorization] = {}
        self._consumed_endpoints: set[str] = set()
        self._active_verified: dict[str, VerifiedEndpointAuthorization] = {}
        self._consumed_verified: set[str] = set()

    def authorize(
        self,
        pre_send: PreSendAuthorization,
        *,
        model_issuer: ModelAuthorizationIssuer,
        profile: ProviderProfile,
        resolver: Resolver,
        now: float,
    ) -> EndpointAuthorization:
        try:
            approved = self._provider_registry.require_registered(profile)
            claim = model_issuer.consume_pre_send(pre_send)
        except (AuthorizationError, ValueError):
            raise EndpointError("INVALID_PRE_SEND_AUTHORIZATION") from None
        if claim["profile_hash"] != approved.canonical_content_hash():
            raise EndpointError("ENDPOINT_PROFILE_MISMATCH")
        parsed = urlsplit(approved.endpoint.base_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            port not in approved.endpoint.allowed_ports
            or parsed.hostname != approved.endpoint.authority
        ):
            raise EndpointError("ENDPOINT_PROFILE_MISMATCH")
        addresses = _resolve(approved, resolver, port)
        nonce = secrets.token_hex(24)
        endpoint = EndpointAuthorization(
            sentinel=_AUTHORIZATION_SENTINEL,
            issuer_id=self._issuer_id,
            nonce=nonce,
            request_hash=str(claim["request_hash"]),
            profile_hash=str(claim["profile_hash"]),
            policy_hash=str(claim["policy_hash"]),
            manifest_hash=str(claim["manifest_hash"]),
            attempt=int(claim["attempt"]),
            scheme=parsed.scheme,
            authority=approved.endpoint.authority,
            port=port,
            addresses=addresses,
            expires_at=now + min(float(approved.budgets.timeout_seconds), 60.0),
        )
        self._active_endpoints[nonce] = endpoint
        return endpoint

    def verify_peer(
        self,
        endpoint: EndpointAuthorization,
        *,
        connected_peer: str,
        resolver: Resolver,
        now: float,
    ) -> VerifiedEndpointAuthorization:
        nonce = getattr(endpoint, "_nonce", None)
        if (
            not isinstance(nonce, str)
            or getattr(endpoint, "_issuer_id", None) != self._issuer_id
            or nonce in self._consumed_endpoints
            or self._active_endpoints.get(nonce) is not endpoint
        ):
            raise EndpointError("INVALID_ENDPOINT_AUTHORIZATION")
        self._active_endpoints.pop(nonce)
        self._consumed_endpoints.add(nonce)
        if now > endpoint._expires_at:
            raise EndpointError("ENDPOINT_AUTHORIZATION_EXPIRED")
        try:
            approved = self._provider_registry.select(
                next(
                    item["selector"]
                    for item in self._provider_registry.safe_inventory()
                    if item["content_sha256"] == endpoint._profile_hash
                )
            )
        except (StopIteration, ValueError):
            raise EndpointError("ENDPOINT_PROFILE_MISMATCH") from None
        current_addresses = _resolve(approved, resolver, endpoint._port)
        if current_addresses != endpoint._addresses:
            raise EndpointError("ENDPOINT_RESOLUTION_CHANGED")
        peer = _validate_address(approved, connected_peer)
        if peer not in endpoint._addresses:
            raise EndpointError("ENDPOINT_PEER_MISMATCH")
        verified_nonce = secrets.token_hex(24)
        verified = VerifiedEndpointAuthorization(
            sentinel=_AUTHORIZATION_SENTINEL,
            issuer_id=self._issuer_id,
            nonce=verified_nonce,
            endpoint=endpoint,
            peer_ip=peer,
        )
        self._active_verified[verified_nonce] = verified
        return verified

    def consume_verified(self, verified: VerifiedEndpointAuthorization) -> dict[str, object]:
        nonce = getattr(verified, "_nonce", None)
        if (
            not isinstance(nonce, str)
            or getattr(verified, "_issuer_id", None) != self._issuer_id
            or nonce in self._consumed_verified
            or self._active_verified.get(nonce) is not verified
        ):
            raise EndpointError("INVALID_VERIFIED_ENDPOINT")
        self._active_verified.pop(nonce)
        self._consumed_verified.add(nonce)
        return {
            "request_hash": verified._request_hash,
            "profile_hash": verified._profile_hash,
            "policy_hash": verified._policy_hash,
            "manifest_hash": verified._manifest_hash,
            "attempt": verified._attempt,
            "scheme": verified._scheme,
            "authority": verified._authority,
            "port": verified._port,
            "peer_ip": verified._peer_ip,
        }


__all__ = [
    "EndpointAuthorization",
    "EndpointAuthorizationIssuer",
    "EndpointError",
    "Resolver",
    "VerifiedEndpointAuthorization",
]
