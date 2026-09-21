"""Authority-issued, scope-bound Evaluation Lab access grants."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN: Final = b"securecode-ai/evaluation-access/v1\x00"


class EvaluationRole(StrEnum):
    TRAINER = "TRAINER"
    CALIBRATOR = "CALIBRATOR"
    LOCKED_TEST_EXECUTOR = "LOCKED_TEST_EXECUTOR"
    REVIEWER = "REVIEWER"


class EvaluationCapability(StrEnum):
    SUBMIT_CANDIDATE = "SUBMIT_CANDIDATE"
    RUN_TRAIN = "RUN_TRAIN"
    RUN_DEV = "RUN_DEV"
    RUN_CALIBRATION = "RUN_CALIBRATION"
    RUN_LOCKED_TEST = "RUN_LOCKED_TEST"
    REVIEW_PROMOTION = "REVIEW_PROMOTION"
    PROMOTE = "PROMOTE"
    READ_LOCKED_EXPECTATIONS = "READ_LOCKED_EXPECTATIONS"


class EvaluationAccessError(ValueError):
    def __init__(self) -> None:
        super().__init__("Evaluation Lab access was denied")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EvaluationAccessGrant:
    authority_id: str
    actor_id: str
    role: EvaluationRole
    capability: EvaluationCapability
    candidate_key: str | None
    dataset_id: str | None
    dataset_sha256: str | None
    run_id: str | None
    expires_at_unix: int
    nonce: str
    grant_sha256: str

    def __post_init__(self) -> None:
        if (
            not all(_identifier(item) for item in (self.authority_id, self.actor_id, self.nonce))
            or type(self.role) is not EvaluationRole
            or type(self.capability) is not EvaluationCapability
            or any(
                item is not None and not _identifier(item)
                for item in (self.candidate_key, self.dataset_id, self.run_id)
            )
            or (self.dataset_sha256 is not None and not _digest(self.dataset_sha256))
            or type(self.expires_at_unix) is not int
            or self.expires_at_unix < 1
            or not _digest(self.grant_sha256)
        ):
            raise EvaluationAccessError()


_GRANTED: dict[EvaluationRole, frozenset[EvaluationCapability]] = {
    EvaluationRole.TRAINER: frozenset(
        {
            EvaluationCapability.SUBMIT_CANDIDATE,
            EvaluationCapability.RUN_TRAIN,
            EvaluationCapability.RUN_DEV,
        }
    ),
    EvaluationRole.CALIBRATOR: frozenset(
        {EvaluationCapability.SUBMIT_CANDIDATE, EvaluationCapability.RUN_CALIBRATION}
    ),
    EvaluationRole.LOCKED_TEST_EXECUTOR: frozenset({EvaluationCapability.RUN_LOCKED_TEST}),
    EvaluationRole.REVIEWER: frozenset(
        {EvaluationCapability.REVIEW_PROMOTION, EvaluationCapability.PROMOTE}
    ),
}


class EvaluationAccessAuthority:
    __slots__ = ("_authority_id", "_key", "_key_check")

    def __init__(self, *, authority_id: str, signing_key: bytes) -> None:
        if not _identifier(authority_id) or type(signing_key) is not bytes or len(signing_key) < 32:
            raise EvaluationAccessError()
        self._authority_id = authority_id
        self._key = bytes(signing_key)
        self._key_check = hashlib.sha256(signing_key).digest()

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("EvaluationAccessAuthority is immutable")
        object.__setattr__(self, name, value)

    def issue(
        self,
        *,
        actor_id: str,
        role: EvaluationRole,
        capability: EvaluationCapability,
        candidate_key: str | None,
        dataset_id: str | None,
        dataset_sha256: str | None,
        run_id: str | None,
        expires_at_unix: int,
        nonce: str,
    ) -> EvaluationAccessGrant:
        if not self._intact() or capability not in _GRANTED.get(role, frozenset()):
            raise EvaluationAccessError()
        material = _material(
            self._authority_id,
            actor_id,
            role,
            capability,
            candidate_key,
            dataset_id,
            dataset_sha256,
            run_id,
            expires_at_unix,
            nonce,
        )
        grant = EvaluationAccessGrant(
            self._authority_id,
            actor_id,
            role,
            capability,
            candidate_key,
            dataset_id,
            dataset_sha256,
            run_id,
            expires_at_unix,
            nonce,
            self._mac(material),
        )
        if expires_at_unix <= int(time.time()):
            raise EvaluationAccessError()
        return grant

    def verify(
        self,
        grant: EvaluationAccessGrant,
        *,
        capability: EvaluationCapability,
        actor_id: str,
        candidate_key: str | None,
        dataset_id: str | None,
        dataset_sha256: str | None,
        run_id: str | None,
        now_unix: int | None = None,
    ) -> EvaluationAccessGrant:
        if not self._intact() or type(grant) is not EvaluationAccessGrant:
            raise EvaluationAccessError()
        copied = EvaluationAccessGrant(**asdict(grant))
        material = _material(
            copied.authority_id,
            copied.actor_id,
            copied.role,
            copied.capability,
            copied.candidate_key,
            copied.dataset_id,
            copied.dataset_sha256,
            copied.run_id,
            copied.expires_at_unix,
            copied.nonce,
        )
        now = int(time.time()) if now_unix is None else now_unix
        if (
            copied.authority_id != self._authority_id
            or copied.capability is not capability
            or copied.capability not in _GRANTED[copied.role]
            or copied.actor_id != actor_id
            or copied.candidate_key != candidate_key
            or copied.dataset_id != dataset_id
            or copied.dataset_sha256 != dataset_sha256
            or copied.run_id != run_id
            or type(now) is not int
            or now >= copied.expires_at_unix
            or not hmac.compare_digest(copied.grant_sha256, self._mac(material))
        ):
            raise EvaluationAccessError()
        return copied

    def _mac(self, material: dict[str, object]) -> str:
        encoded = json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hmac.new(self._key, _DOMAIN + encoded, hashlib.sha256).hexdigest()

    def _intact(self) -> bool:
        try:
            return type(self) is EvaluationAccessAuthority and hmac.compare_digest(
                hashlib.sha256(self._key).digest(), self._key_check
            )
        except Exception:
            return False


def require_access(
    authority: EvaluationAccessAuthority,
    grant: EvaluationAccessGrant,
    **scope: object,
) -> EvaluationAccessGrant:
    if type(authority) is not EvaluationAccessAuthority:
        raise EvaluationAccessError()
    return authority.verify(grant, **scope)  # type: ignore[arg-type]


def _material(
    authority_id: str,
    actor_id: str,
    role: EvaluationRole,
    capability: EvaluationCapability,
    candidate_key: str | None,
    dataset_id: str | None,
    dataset_sha256: str | None,
    run_id: str | None,
    expires_at_unix: int,
    nonce: str,
) -> dict[str, object]:
    return {
        "actor_id": actor_id,
        "authority_id": authority_id,
        "candidate_key": candidate_key,
        "capability": capability.value,
        "dataset_id": dataset_id,
        "dataset_sha256": dataset_sha256,
        "expires_at_unix": expires_at_unix,
        "nonce": nonce,
        "role": role.value,
        "run_id": run_id,
    }


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


__all__ = [
    "EvaluationAccessAuthority",
    "EvaluationAccessError",
    "EvaluationAccessGrant",
    "EvaluationCapability",
    "EvaluationRole",
    "require_access",
]
