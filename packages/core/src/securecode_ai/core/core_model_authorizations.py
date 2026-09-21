"""Issuer-owned immutable model authorization proofs."""

from __future__ import annotations

from typing import Any, SupportsIndex

from securecode_ai.contracts import DataClass, ModelPreflightResult

from .core_model_protocols import _PERMIT_SENTINEL


class PreContextAuthorization:
    """Issuer-owned result; only an eligible live instance can authorize send."""

    __slots__ = (
        "_destination",
        "_execution_identity_hash",
        "_issuer_id",
        "_max_bytes",
        "_nonce",
        "_planned_transforms",
        "_policy_hash",
        "_profile_hash",
        "_request_hash",
        "_request_scope",
        "_required_data_class",
        "_result",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("authorization objects are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        sentinel: object,
        result: ModelPreflightResult,
        issuer_id: str,
        nonce: str | None,
        request_hash: str,
        request_scope: tuple[str, str, str, str, int] | None,
        profile_hash: str,
        policy_hash: str,
        destination: str,
        execution_identity_hash: str,
        required_data_class: DataClass,
        planned_transforms: tuple[str, ...],
        max_bytes: int,
    ) -> None:
        if sentinel is not _PERMIT_SENTINEL:
            raise TypeError("authorization objects are issuer-owned")
        self._result = result
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = request_hash
        self._request_scope = request_scope
        self._profile_hash = profile_hash
        self._policy_hash = policy_hash
        self._destination = destination
        self._execution_identity_hash = execution_identity_hash
        self._required_data_class = required_data_class
        self._planned_transforms = planned_transforms
        self._max_bytes = max_bytes

    @property
    def result(self) -> ModelPreflightResult:
        return self._result

    def __repr__(self) -> str:
        return f"PreContextAuthorization({self.result.eligibility.value})"

    def __copy__(self) -> PreContextAuthorization:
        raise TypeError("authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PreContextAuthorization:
        del memo
        raise TypeError("authorizations cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("authorizations cannot be serialized")


class PreSendAuthorization:
    """Issuer-owned, single-use proof binding one exact metadata-only manifest."""

    __slots__ = (
        "_attempt",
        "_issuer_id",
        "_manifest_hash",
        "_nonce",
        "_policy_hash",
        "_profile_hash",
        "_request_hash",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("authorization objects are immutable")
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
    ) -> None:
        if sentinel is not _PERMIT_SENTINEL:
            raise TypeError("authorization objects are issuer-owned")
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = request_hash
        self._profile_hash = profile_hash
        self._policy_hash = policy_hash
        self._manifest_hash = manifest_hash
        self._attempt = attempt

    @property
    def manifest_hash(self) -> str:
        return self._manifest_hash

    def __repr__(self) -> str:
        return "PreSendAuthorization(<opaque>)"

    def __copy__(self) -> PreSendAuthorization:
        raise TypeError("authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PreSendAuthorization:
        del memo
        raise TypeError("authorizations cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("authorizations cannot be serialized")
