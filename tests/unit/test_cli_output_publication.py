"""SC-CLI-005 exclusive output publication controls."""

import io
from pathlib import Path

import pytest
from securecode_ai.cli.application import main
from securecode_ai.cli.repair import RepairCli


def run(output: Path) -> tuple[int, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = main(
        ["scan", "fixture-target", "--format", "json", "--output", str(output), "--json"],
        stdout=stdout,
        stderr=stderr,
        repair=RepairCli(scan=lambda target: {"exit_code": 0, "run_id": "public-fixture"}),
    )
    return code, stdout.getvalue()


def test_file_appearing_after_exists_check_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "source.py"
    original = b"original source must remain intact\n"
    output.write_bytes(original)
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: False if self == output else real_exists(self))
    code, _ = run(output)
    assert output.read_bytes() == original
    assert code == 4


def test_exclusive_new_output_contains_exact_rendered_bytes(tmp_path: Path) -> None:
    output = tmp_path / "audit.json"
    code, stdout = run(output)
    assert code == 0
    assert output.read_bytes() == stdout.encode("utf-8")


def test_missing_output_parent_fails_closed(tmp_path: Path) -> None:
    output = tmp_path / "absent" / "audit.json"
    code, _ = run(output)
    assert code == 4
    assert not output.exists()


def test_dangling_leaf_symlink_is_never_followed(tmp_path: Path) -> None:
    output = tmp_path / "audit.json"
    redirected = tmp_path / "redirected.json"
    try:
        output.symlink_to(redirected)
    except OSError as error:
        pytest.skip(f"dangling symlink creation is unavailable: {error}")

    code, _ = run(output)

    assert code == 4
    assert output.is_symlink()
    assert not redirected.exists()


def test_dangling_leaf_created_after_symlink_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "audit.json"
    redirected = tmp_path / "redirected.json"
    original = Path.is_symlink
    created = False

    def race(path: Path) -> bool:
        nonlocal created
        if path == output and not created:
            try:
                path.symlink_to(redirected)
            except OSError as error:
                pytest.skip(f"symlink race setup unavailable: {error}")
            created = True
            return False
        return original(path)

    monkeypatch.setattr(Path, "is_symlink", race)
    code, _ = run(output)
    assert not redirected.exists()
    assert original(output)
    assert code == 4
