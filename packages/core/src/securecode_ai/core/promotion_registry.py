"""Immutable compare-and-set promotion alias registry."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .promotion_decision import (
    PromotionAction,
    PromotionDecisionAuthority,
    PromotionDecisionReceipt,
)
from .promotion_registry_store import (
    InMemoryPromotionStore,
    PromotionAlias,
    PromotionAliasStore,
    PromotionStoreError,
    SqlitePromotionStore,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class PromotionRegistryError(ValueError):
    def __init__(self) -> None:
        super().__init__("Promotion alias update was rejected")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class PromotionAliasReceipt:
    applied: bool
    alias: PromotionAlias | None
    decision: PromotionDecisionReceipt


class PromotionAliasRegistry:
    """Verify decisions and delegate atomic state changes to an injected store."""

    def __init__(
        self,
        authority: PromotionDecisionAuthority,
        store: PromotionAliasStore,
    ) -> None:
        if type(authority) is not PromotionDecisionAuthority or not isinstance(
            store, InMemoryPromotionStore | SqlitePromotionStore
        ):
            raise PromotionRegistryError()
        self._authority = authority
        self._store = store

    def compare_and_set(
        self,
        *,
        alias: str,
        expected_revision: int,
        decision: PromotionDecisionReceipt,
    ) -> PromotionAliasReceipt:
        snapshot = self._authority.verify_and_snapshot(decision)
        if (
            type(alias) is not str
            or _ID.fullmatch(alias) is None
            or type(expected_revision) is not int
            or expected_revision < 0
            or snapshot is None
            or snapshot.target_alias != alias
            or snapshot.expected_revision != expected_revision
        ):
            raise PromotionRegistryError()
        if snapshot.action is not PromotionAction.PROMOTE:
            return PromotionAliasReceipt(False, self.resolve(alias), snapshot)
        if not _promotion_bindings_valid(snapshot):
            raise PromotionRegistryError()
        try:
            return PromotionAliasReceipt(True, self._store.apply(snapshot), snapshot)
        except PromotionStoreError:
            raise PromotionRegistryError() from None

    def resolve(self, alias: str) -> PromotionAlias | None:
        if type(alias) is not str or _ID.fullmatch(alias) is None:
            raise PromotionRegistryError()
        try:
            return self._store.resolve(alias)
        except PromotionStoreError:
            raise PromotionRegistryError() from None


def _promotion_bindings_valid(decision: PromotionDecisionReceipt) -> bool:
    request = decision.request
    candidate = request.candidate
    pareto = request.pareto
    approval = request.appsec
    return (
        decision.action is PromotionAction.PROMOTE
        and decision.content_sha256 == candidate.content_sha256
        and decision.evidence_sha256 == approval.evidence_sha256
        and pareto.complete
        and pareto.candidate_content_sha256 == candidate.content_sha256
        and pareto.security_regressions == 0
        and pareto.unsafe_patches == 0
        and pareto.protected_data_accesses == 0
        and approval.candidate_id == candidate.candidate_id
        and approval.candidate_version == candidate.version
        and approval.candidate_content_sha256 == candidate.content_sha256
        and approval.reviewer_id not in {candidate.owner_id, candidate.evaluator_id}
        and candidate.owner_id != candidate.evaluator_id
    )


__all__ = [
    "InMemoryPromotionStore",
    "PromotionAlias",
    "PromotionAliasReceipt",
    "PromotionAliasRegistry",
    "PromotionRegistryError",
    "SqlitePromotionStore",
]
