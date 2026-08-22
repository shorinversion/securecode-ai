"""Security and determinism tests for P2.1 repository intake."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from securecode_ai.adapters import FileSystemRepositoryIntake
from securecode_ai.core import InventoryLimits, RepositoryIntakeError, RepositoryIntakeErrorCode


def _intake(**changes: int) -> FileSystemRepositoryIntake:
    defaults = {
        "max_files": 32,
        "max_directories": 16,
        "max_depth": 8,
        "max_path_bytes": 256,
        "max_file_bytes": 4096,
        "max_total_bytes": 16384,
    }
    defaults.update(changes)
    return FileSystemRepositoryIntake(InventoryLimits(**defaults))


def test_inventory_is_relative_sorted_content_bound_and_repeatable(tmp_path: Path) -> None:
    (tmp_path / "z.bin").write_bytes(b"\x00\xff")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_bytes(b"print('data only')\n")
    first = _intake().inventory(tmp_path)
    second = _intake().inventory(tmp_path)
    assert first == second
    assert [item.path for item in first.files] == ["src/a.py", "z.bin"]
    assert first.total_bytes == 21
    assert len(first.tree_sha256) == 64
    assert all(not Path(item.path).is_absolute() for item in first.files)


def test_empty_repository_has_stable_empty_digest(tmp_path: Path) -> None:
    inventory = _intake().inventory(tmp_path)
    assert inventory.files == ()
    assert inventory.total_bytes == 0
    expected = "".join(
        (
            "e3b0c442",
            "98fc1c14",
            "9afbf4c8",
            "996fb924",
            "27ae41e4",
            "649b934c",
            "a495991b",
            "7852b855",
        )
    )
    assert inventory.tree_sha256 == expected


def test_archive_is_opaque_and_lifecycle_script_never_executes(tmp_path: Path) -> None:
    sentinel = tmp_path.parent / "executed"
    (tmp_path / "package.json").write_text(
        '{"scripts":{"preinstall":"touch ../executed"}}', encoding="utf-8"
    )
    (tmp_path / "payload.zip").write_bytes(b"PK\x03\x04../outside")
    inventory = _intake().inventory(tmp_path)
    assert {item.path for item in inventory.files} == {"package.json", "payload.zip"}
    assert not sentinel.exists()
    assert not (tmp_path.parent / "outside").exists()


def test_symlink_and_nested_repository_fail_closed_without_path_echo(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.LINK_UNSUPPORTED
    assert str(tmp_path) not in str(raised.value)

    link.unlink()
    nested = tmp_path / "vendor"
    nested.mkdir()
    (nested / ".git").write_text("gitdir: ../../external", encoding="utf-8")
    with pytest.raises(RepositoryIntakeError) as nested_error:
        _intake().inventory(tmp_path)
    assert nested_error.value.code is RepositoryIntakeErrorCode.NESTED_REPOSITORY


def test_symlink_root_is_rejected_without_reading_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "unreadable-payload").write_bytes(b"must-not-be-read")
    root_link = tmp_path / "root-link"
    try:
        root_link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(root_link)
    assert raised.value.code is RepositoryIntakeErrorCode.LINK_UNSUPPORTED


@pytest.mark.parametrize(
    ("limits", "code"),
    [
        ({"max_files": 1}, RepositoryIntakeErrorCode.FILE_LIMIT),
        ({"max_file_bytes": 2}, RepositoryIntakeErrorCode.FILE_SIZE_LIMIT),
        ({"max_total_bytes": 3}, RepositoryIntakeErrorCode.TOTAL_SIZE_LIMIT),
        ({"max_path_bytes": 3}, RepositoryIntakeErrorCode.PATH_LIMIT),
        ({"max_depth": 1}, RepositoryIntakeErrorCode.DEPTH_LIMIT),
    ],
)
def test_resource_budgets_fail_closed(
    tmp_path: Path,
    limits: dict[str, int],
    code: RepositoryIntakeErrorCode,
) -> None:
    (tmp_path / "one").write_bytes(b"123")
    (tmp_path / "deep").mkdir()
    (tmp_path / "deep" / "two").write_bytes(b"45")
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake(**limits).inventory(tmp_path)
    assert raised.value.code is code


def test_fifo_or_other_special_file_is_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.ENTRY_TYPE_UNSUPPORTED


def test_directory_budget_and_case_collision_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(RepositoryIntakeError) as directory_error:
        _intake(max_directories=1).inventory(tmp_path)
    assert directory_error.value.code is RepositoryIntakeErrorCode.DIRECTORY_LIMIT

    if os.path.normcase("A") != os.path.normcase("a"):
        (tmp_path / "b").rmdir()
        (tmp_path / "A").write_bytes(b"upper")
        (tmp_path / "a" / "placeholder").write_bytes(b"nested")
        with pytest.raises(RepositoryIntakeError) as collision_error:
            _intake().inventory(tmp_path)
        assert collision_error.value.code is RepositoryIntakeErrorCode.PATH_INVALID


def test_root_and_os_failures_are_fixed_and_non_echoing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_root = tmp_path / "not-a-directory"
    file_root.write_bytes(b"data")
    with pytest.raises(RepositoryIntakeError) as root_error:
        _intake().inventory(file_root)
    assert root_error.value.code is RepositoryIntakeErrorCode.ROOT_INVALID

    canary = "source-path-canary"

    def fail_scandir(path: object) -> object:
        raise OSError(canary)

    monkeypatch.setattr(os, "scandir", fail_scandir)
    with pytest.raises(RepositoryIntakeError) as io_error:
        _intake().inventory(tmp_path)
    assert io_error.value.code is RepositoryIntakeErrorCode.IO_FAILURE
    assert canary not in str(io_error.value)
    assert io_error.value.__cause__ is None
    assert io_error.value.__context__ is None


def test_limits_and_inventory_values_are_strictly_immutable() -> None:
    limits = InventoryLimits(2, 2, 2, 64, 64, 128)
    with pytest.raises((AttributeError, TypeError)):
        limits.max_files = 3  # type: ignore[misc]
    with pytest.raises(ValueError):
        InventoryLimits(True, 2, 2, 64, 64, 128)


def test_intake_snapshots_limits_against_retained_object_mutation(tmp_path: Path) -> None:
    limits = InventoryLimits(1, 2, 2, 64, 64, 128)
    intake = FileSystemRepositoryIntake(limits)
    object.__setattr__(limits, "max_files", 100)
    (tmp_path / "one").write_bytes(b"1")
    (tmp_path / "two").write_bytes(b"2")
    with pytest.raises(RepositoryIntakeError) as raised:
        intake.inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.FILE_LIMIT
