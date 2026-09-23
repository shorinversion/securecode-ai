from __future__ import annotations

from threading import Event, Thread

from securecode_ai.server.ports import VerifiedIdentity
from securecode_ai.server.reloading_identity import ReloadingIdentityVerifier


class _BlockingVerifier:
    def __init__(self, identity: VerifiedIdentity, entered: Event, release: Event) -> None:
        self._identity = identity
        self._entered = entered
        self._release = release

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        del token
        self._entered.set()
        if not self._release.wait(timeout=2):
            raise AssertionError("test verifier was not released")
        return self._identity


class _Verifier:
    def __init__(self, identity: VerifiedIdentity) -> None:
        self._identity = identity

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        del token
        return self._identity


def test_rotation_serializes_reload_after_inflight_old_verifier() -> None:
    entered = Event()
    release = Event()
    old = VerifiedIdentity("old", "tenant-old", frozenset({"viewer"}))
    new = VerifiedIdentity("new", "tenant-new", frozenset({"viewer"}))
    initial = _Verifier(old)
    in_flight = _BlockingVerifier(old, entered, release)
    rotated = _Verifier(new)
    loaded: list[_Verifier | _BlockingVerifier] = [initial, in_flight, rotated]
    load_count = 0

    def load() -> _Verifier | _BlockingVerifier:
        nonlocal load_count
        verifier = loaded[load_count]
        load_count += 1
        return verifier

    wrapper = ReloadingIdentityVerifier(load)
    first_result: list[VerifiedIdentity | None] = []
    second_result: list[VerifiedIdentity | None] = []
    second_done = Event()

    first = Thread(target=lambda: first_result.append(wrapper.verify_bearer("old-token")))

    def verify_rotated() -> None:
        second_result.append(wrapper.verify_bearer("new-token"))
        second_done.set()

    second = Thread(target=verify_rotated)
    first.start()
    assert entered.wait(timeout=2)
    second.start()

    assert not second_done.wait(timeout=0.1)
    assert load_count == 2

    release.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert not first.is_alive() and not second.is_alive()
    assert first_result == [old]
    assert second_result == [new]
    assert load_count == 3
