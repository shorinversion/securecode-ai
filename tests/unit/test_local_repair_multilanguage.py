"""Repair validation scanner accepts the production TypeScript extensions."""

from __future__ import annotations

from pathlib import Path

import pytest
from securecode_ai.adapters.local_repair_contracts import _local_cwe89_parameter_binding_oracle
from securecode_ai.adapters.local_repair_root_cause_oracle import (
    RootCauseOracleError,
    _scan_signal_identities,
)
from securecode_ai.adapters.local_repair_security_scan import (
    SecurityScanError,
    scan_cwe89_repository,
)


@pytest.mark.parametrize("suffix", (".mts", ".cts"))
def test_repair_scanner_and_independent_oracle_scan_node_typescript_extensions(
    tmp_path: Path, suffix: str
) -> None:
    source = (
        b"const id: string = request.query.id;\n"
        b"const sql = `SELECT * FROM users WHERE id = ${id}`;\n"
        b"db.execute(sql);\n"
    )
    relative_path = f"src/query{suffix}"
    (tmp_path / "src").mkdir()
    (tmp_path / relative_path).write_bytes(source)
    manifest = {
        "finding": {
            "repository_revision": {"repository_id": "example/node-app"},
            "locations": [{"path": relative_path}],
        }
    }

    scan_sha256, signal_count = scan_cwe89_repository(tmp_path, manifest, "a" * 40)
    identities = _scan_signal_identities(tmp_path, manifest, "a" * 40)

    assert len(scan_sha256) == 64
    assert signal_count == len(identities) == 1
    assert identities[0].path == relative_path


@pytest.mark.parametrize("suffix", (".mts", ".cts"))
def test_repair_contract_distinguishes_vulnerable_and_bound_node_typescript(
    suffix: str,
) -> None:
    vulnerable = f"db.execute(`SELECT * FROM users WHERE id = ${'{'}id{'}'}`);".encode()
    fixed = b"db.execute('SELECT * FROM users WHERE id = ?', [id]);"

    assert _local_cwe89_parameter_binding_oracle({f"src/query{suffix}": vulnerable}) is False
    assert _local_cwe89_parameter_binding_oracle({f"src/query{suffix}": fixed}) is True


def test_repair_scanner_and_contract_accept_python_stub_files(tmp_path: Path) -> None:
    source = (
        b"def lookup(request, db):\n"
        b' id = request.args.get("id")\n'
        b' db.execute(f"SELECT * FROM users WHERE id = {id}")\n'
    )
    relative_path = "src/query.pyi"
    (tmp_path / "src").mkdir()
    (tmp_path / relative_path).write_bytes(source)
    manifest = {
        "finding": {
            "repository_revision": {"repository_id": "example/python-app"},
            "locations": [{"path": relative_path}],
        }
    }

    scan_sha256, signal_count = scan_cwe89_repository(tmp_path, manifest, "a" * 40)
    identities = _scan_signal_identities(tmp_path, manifest, "a" * 40)

    assert len(scan_sha256) == 64
    assert signal_count == len(identities) == 1
    assert _local_cwe89_parameter_binding_oracle({relative_path: source}) is False


def test_repair_scan_and_oracle_do_not_follow_symlink_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    relative_path = "src/query.py"
    source = b"def lookup(request, db):\n db.execute(f\"SELECT {request.args.get('id')}\")\n"
    (tmp_path / "src").mkdir()
    (tmp_path / relative_path).write_bytes(source)
    manifest = {
        "finding": {
            "repository_revision": {"repository_id": "example/python-app"},
            "locations": [{"path": relative_path}],
        }
    }
    original_is_symlink = Path.is_symlink

    def mark_finding_path_as_symlink(path: Path) -> bool:
        return path.as_posix().endswith(relative_path) or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", mark_finding_path_as_symlink)

    with pytest.raises(SecurityScanError):
        scan_cwe89_repository(tmp_path, manifest, "a" * 40)
    with pytest.raises(RootCauseOracleError):
        _scan_signal_identities(tmp_path, manifest, "a" * 40)
