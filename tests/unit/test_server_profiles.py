"""P6.5 profile immutability and policy resolution controls."""

from __future__ import annotations

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
