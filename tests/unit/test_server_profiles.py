"""P6.5 profile immutability and policy resolution controls."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import cast

import pytest
from securecode_ai.server.policy_store import PolicyStore
from securecode_ai.server.profiles import ProfileConflict, RolloutMode, ScanProfile


def test_profiles_are_immutable_and_repository_assignment_overrides_default() -> None:
    store = PolicyStore()
    advisory = ScanProfile.build(
        tenant_id="t",
        profile_id="default",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content={"rules": ["a"]},
    )
    strict = ScanProfile.build(
        tenant_id="t",
        profile_id="strict",
        version=1,
        rollout=RolloutMode.STRICT,
        calibrated=True,
        content={"rules": ["b"]},
    )
    store.create(advisory, idempotency_key="key")
    assert store.create(advisory, idempotency_key="key") == advisory
    store.create(strict, idempotency_key="key-2")
    store.set_tenant_default(tenant_id="t", profile_id="default", version=1)
    store.assign_repository(tenant_id="t", repository_id="r", profile_id="strict", version=1)
    assert (
        store.resolve(tenant_id="t", repository_id="r")["content_sha256"] == strict.content_sha256
    )
    assert store.resolve_profile(tenant_id="t", repository_id="r") == strict
    assert store.resolve_profile(tenant_id="t", repository_id="other") == advisory


def test_profile_content_is_deeply_immutable_and_detached_from_builder_input() -> None:
    source: dict[str, object] = {"rules": [{"severity": "high"}]}
    profile = ScanProfile.build(
        tenant_id="t",
        profile_id="p",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content=source,
    )
    source_rules = cast(list[object], source["rules"])
    cast(dict[str, object], source_rules[0])["severity"] = "low"

    profile_rules = cast(tuple[object, ...], profile.content["rules"])
    profile_rule = cast(Mapping[str, object], profile_rules[0])
    assert profile_rule["severity"] == "high"
    with pytest.raises(TypeError):
        cast(dict[str, object], profile_rule)["severity"] = "critical"


def test_precalibration_blocking_profile_and_divergent_version_fail_closed() -> None:
    with pytest.raises(ValueError):
        ScanProfile.build(
            tenant_id="t",
            profile_id="bad",
            version=1,
            rollout=RolloutMode.NEW_CODE,
            calibrated=False,
            content={},
        )
    store = PolicyStore()
    first = ScanProfile.build(
        tenant_id="t",
        profile_id="p",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content={},
    )
    store.create(first, idempotency_key="key")
    with pytest.raises(ProfileConflict):
        store.create(
            ScanProfile.build(
                tenant_id="t",
                profile_id="p",
                version=1,
                rollout=RolloutMode.ADVISORY,
                calibrated=False,
                content={"changed": True},
            ),
            idempotency_key="key",
        )


def test_policy_store_rejects_content_tampering_on_read() -> None:
    connection = sqlite3.connect(":memory:")
    store = PolicyStore(connection)
    profile = ScanProfile.build(
        tenant_id="t",
        profile_id="p",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content={"rules": ["approved"]},
    )
    store.create(profile, idempotency_key="create-profile")
    store.set_tenant_default(tenant_id="t", profile_id="p", version=1)
    connection.execute(
        "UPDATE scan_policy_versions SET content_json = ? WHERE tenant_id = ? AND profile_id = ?",
        ('{"rules":["tampered"]}', "t", "p"),
    )

    with pytest.raises(ProfileConflict, match="stored policy content integrity failed"):
        store.resolve_profile(tenant_id="t", repository_id="r")


def test_policy_store_rejects_malformed_content_on_read() -> None:
    connection = sqlite3.connect(":memory:")
    store = PolicyStore(connection)
    profile = ScanProfile.build(
        tenant_id="t",
        profile_id="p",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content={"rules": ["approved"]},
    )
    store.create(profile, idempotency_key="create-profile")
    store.set_tenant_default(tenant_id="t", profile_id="p", version=1)
    connection.execute(
        "UPDATE scan_policy_versions SET content_json = ? WHERE tenant_id = ? AND profile_id = ?",
        ("{malformed", "t", "p"),
    )

    with pytest.raises(ProfileConflict, match="stored policy content is invalid"):
        store.resolve_profile(tenant_id="t", repository_id="r")
