"""Fail-closed side-effect guards for the unit-test process."""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest


def _deny_side_effect(*_args: object, **_kwargs: object) -> NoReturn:
    raise RuntimeError("network and child-process side effects are denied in unit tests")


@pytest.fixture(autouse=True)
def isolate_unit_test_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Move writes to a temporary directory and deny common network/process APIs."""

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(socket, "socket", _deny_side_effect)
    monkeypatch.setattr(socket, "create_connection", _deny_side_effect)
    monkeypatch.setattr(socket, "getaddrinfo", _deny_side_effect)
    monkeypatch.setattr(subprocess, "Popen", _deny_side_effect)
    monkeypatch.setattr(os, "system", _deny_side_effect)
    yield
