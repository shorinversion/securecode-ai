from __future__ import annotations

import os
from pathlib import Path

import pytest
from securecode_ai.worker.liveness import HEARTBEAT_FILE, heartbeat_path, touch


def test_touch_creates_a_private_heartbeat_with_the_given_timestamp(tmp_path: Path) -> None:
    touch(tmp_path, now=100.0)
    target = tmp_path / HEARTBEAT_FILE

    assert heartbeat_path(tmp_path) == target
    assert target.stat().st_mtime == 100.0
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_liveness_requires_a_real_absolute_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        heartbeat_path(Path("relative"))
    with pytest.raises(ValueError):
        heartbeat_path(tmp_path / "missing")


def test_touch_rejects_an_invalid_clock(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        touch(tmp_path, now=-1.0)
    with pytest.raises(ValueError):
        touch(tmp_path, now=float("nan"))
