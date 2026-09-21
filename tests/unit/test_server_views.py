"""P6.9 safe developer/API views."""

from __future__ import annotations

import pytest
from securecode_ai.server.identity import Principal, Role
from securecode_ai.server.query_service import InMemoryViewRepository, QueryService, SafeNotFound
from securecode_ai.server.views import RunView, ViewOutcome


def test_incomplete_pass_never_renders_clean_and_cross_tenant_is_not_found() -> None:
    run = RunView("tenant-a", "repo", "run", "a" * 64, "b" * 40, ViewOutcome.PASS, False)
    service = QueryService(InMemoryViewRepository((run,)))
    allowed = Principal("viewer", "tenant-a", frozenset({Role.VIEWER}), frozenset({"repo"}))
    assert not service.run_detail(allowed, "repo", "run")["clean"]
    denied = Principal("viewer", "tenant-b", frozenset({Role.VIEWER}), frozenset({"repo"}))
    with pytest.raises(SafeNotFound):
        service.run_detail(denied, "repo", "run")
