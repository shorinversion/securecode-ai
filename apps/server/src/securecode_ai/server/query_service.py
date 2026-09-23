"""Tenant-scoped source-free query composition with opaque stable cursors."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .identity import Principal
from .views import FindingView, RunView


class SafeNotFound(Exception):
    pass


class QueryValidationErrorCode(StrEnum):
    CURSOR_INVALID = "CURSOR_INVALID"
    LIMIT_INVALID = "LIMIT_INVALID"


class QueryValidationError(ValueError):
    """Bounded pagination failure that never carries caller-controlled data."""

    __slots__ = ("code",)

    def __init__(self, code: QueryValidationErrorCode) -> None:
        if type(code) is not QueryValidationErrorCode:
            raise TypeError("query validation code is invalid")
        self.code = code
        super().__init__("query pagination is invalid")


class ViewRepository(Protocol):
    def runs(self, tenant_id: str, repository_id: str) -> tuple[RunView, ...]: ...
    def findings(
        self, tenant_id: str, repository_id: str, run_id: str
    ) -> tuple[FindingView, ...]: ...


@dataclass
class InMemoryViewRepository:
    run_values: tuple[RunView, ...] = ()
    finding_values: tuple[FindingView, ...] = ()

    def runs(self, tenant_id: str, repository_id: str) -> tuple[RunView, ...]:
        return tuple(
            sorted(
                (
                    value
                    for value in self.run_values
                    if value.tenant_id == tenant_id and value.repository_id == repository_id
                ),
                key=lambda value: value.run_id,
            )
        )

    def findings(self, tenant_id: str, repository_id: str, run_id: str) -> tuple[FindingView, ...]:
        return tuple(
            sorted(
                (
                    value
                    for value in self.finding_values
                    if value.tenant_id == tenant_id
                    and value.repository_id == repository_id
                    and value.run_id == run_id
                ),
                key=lambda value: value.finding_id,
            )
        )


class QueryService:
    def __init__(self, repository: ViewRepository) -> None:
        self._repository = repository

    def list_runs(
        self, principal: Principal, repository_id: str, cursor: str | None = None, limit: int = 50
    ) -> dict[str, object]:
        self._allow(principal, "runs.read", repository_id)
        values = self._repository.runs(principal.tenant_id, repository_id)
        return _page([item.json_ready() for item in values], cursor, limit)

    def run_detail(
        self, principal: Principal, repository_id: str, run_id: str
    ) -> dict[str, object]:
        self._allow(principal, "runs.read", repository_id)
        for item in self._repository.runs(principal.tenant_id, repository_id):
            if item.run_id == run_id:
                return item.json_ready()
        raise SafeNotFound()

    def list_findings(
        self,
        principal: Principal,
        repository_id: str,
        run_id: str,
        cursor: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        self._allow(principal, "runs.findings.read", repository_id)
        return _page(
            [
                item.json_ready()
                for item in self._repository.findings(principal.tenant_id, repository_id, run_id)
            ],
            cursor,
            limit,
        )

    def finding_detail(
        self, principal: Principal, repository_id: str, finding_id: str
    ) -> dict[str, object]:
        self._allow(principal, "findings.read", repository_id)
        for run in self._repository.runs(principal.tenant_id, repository_id):
            for finding in self._repository.findings(
                principal.tenant_id, repository_id, run.run_id
            ):
                if finding.finding_id == finding_id:
                    return finding.json_ready()
        raise SafeNotFound()

    def _allow(self, principal: Principal, action: str, repository_id: str) -> None:
        if not principal.allows(action=action, repository_id=repository_id):
            raise SafeNotFound()


def _page(values: list[dict[str, object]], cursor: str | None, limit: int) -> dict[str, object]:
    start = _decode(cursor)
    size = _page_size(limit)
    page = values[start : start + size]
    next_cursor = _encode(start + len(page)) if start + len(page) < len(values) else None
    return {"items": page, "next_cursor": next_cursor}


def _encode(value: int) -> str:
    return base64.urlsafe_b64encode(str(value).encode("ascii")).decode("ascii").rstrip("=")


def _page_size(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 100:
        raise QueryValidationError(QueryValidationErrorCode.LIMIT_INVALID)
    return value


def _decode(value: object) -> int:
    if value is None:
        return 0
    if (
        type(value) is not str
        or not value
        or len(value) > 256
        or any(
            not character.isascii() or (not character.isalnum() and character not in "-_")
            for character in value
        )
    ):
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID) from None
    if not decoded or not decoded.isascii() or not decoded.isdecimal():
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID)
    if len(decoded) > 1 and decoded.startswith("0"):
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID)
    try:
        offset = int(decoded)
    except ValueError:
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID) from None
    if offset > 9_223_372_036_854_775_807 or _encode(offset) != value:
        raise QueryValidationError(QueryValidationErrorCode.CURSOR_INVALID)
    return offset
