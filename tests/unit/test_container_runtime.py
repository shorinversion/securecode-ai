from __future__ import annotations

import pytest
from securecode_ai.server.runtime import load_settings


def test_runtime_rejects_unvalidated_environment() -> None:
    with pytest.raises(ValueError):
        load_settings({"SECURECODE_SERVER_PORT": "zero"})


def test_runtime_accepts_only_declared_paths_and_port() -> None:
    assert (
        load_settings(
            {
                "SECURECODE_SERVER_HOST": "127.0.0.1",
                "SECURECODE_SERVER_PORT": "8080",
                "SECURECODE_DATA_DIR": "/data",
                "SECURECODE_TMP_DIR": "/tmp",
            }
        ).port
        == 8080
    )
