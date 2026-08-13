"""Security oracles for the canonical unit-test environment."""

from __future__ import annotations

import os
import socket
import subprocess

import pytest

SENSITIVE_OR_INJECTABLE_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "PYTHONPATH",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "SECURECODE_P1_SECRET_CANARY",
)


def test_child_environment_is_sanitized() -> None:
    assert os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert not (set(SENSITIVE_OR_INJECTABLE_NAMES) & os.environ.keys())


@pytest.mark.parametrize(
    "operation",
    [
        lambda: socket.socket(),
        lambda: socket.getaddrinfo("example.com", 443),
        lambda: subprocess.Popen(["python", "-V"]),
    ],
)
def test_network_and_child_processes_are_denied(operation: object) -> None:
    with pytest.raises(RuntimeError, match="side effects are denied"):
        operation()  # type: ignore[operator]
