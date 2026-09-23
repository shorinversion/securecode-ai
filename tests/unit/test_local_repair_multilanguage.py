"""Repair validation scanner accepts the production TypeScript extensions."""

from __future__ import annotations

from pathlib import Path

import pytest
from securecode_ai.adapters.local_repair_root_cause_oracle import _scan_signal_identities
from securecode_ai.adapters.local_repair_security_scan import scan_cwe89_repository


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
