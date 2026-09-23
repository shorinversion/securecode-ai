from __future__ import annotations

import os
import runpy
import stat
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _materializer() -> Callable[[Path, MutableMapping[str, str] | None], None]:
    module = runpy.run_path(str(ROOT / "deploy/docker/entrypoint.py"))
    return cast(
        Callable[[Path, MutableMapping[str, str] | None], None],
        module["_materialize_tls_private_key"],
    )


def test_compose_style_tls_key_is_materialized_with_private_permissions(tmp_path: Path) -> None:
    source = tmp_path / "compose-secret.key"
    source.write_bytes(b"private-key-data")
    source.chmod(0o444)
    data_dir = tmp_path / "state"
    data_dir.mkdir(mode=0o700)
    environment = {"SECURECODE_TLS_KEY_FILE": str(source)}

    _materializer()(data_dir, environment)

    target = data_dir / "server-tls.key"
    assert environment["SECURECODE_TLS_KEY_FILE"] == str(target)
    assert target.read_bytes() == b"private-key-data"
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_tls_key_materialization_rejects_oversized_input_without_rewriting_environment(
    tmp_path: Path,
) -> None:
    source = tmp_path / "oversized.key"
    source.write_bytes(b"x" * 65_537)
    data_dir = tmp_path / "state"
    data_dir.mkdir(mode=0o700)
    environment = {"SECURECODE_TLS_KEY_FILE": str(source)}

    with pytest.raises(OSError):
        _materializer()(data_dir, environment)

    assert environment["SECURECODE_TLS_KEY_FILE"] == str(source)
    assert not (data_dir / "server-tls.key").exists()


def test_tls_key_materialization_is_a_noop_without_tls_configuration(tmp_path: Path) -> None:
    environment: dict[str, str] = {}

    _materializer()(tmp_path, environment)

    assert environment == {}
