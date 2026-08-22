"""Security and determinism tests for P2.1 repository intake."""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

import pytest
from securecode_ai.adapters import FileSystemRepositoryIntake
from securecode_ai.core import (
    InventoryLimits,
    RepositoryFile,
    RepositoryIntakeError,
    RepositoryIntakeErrorCode,
)


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


@pytest.mark.parametrize(
    "unsafe",
    [
        "../escape",
        "a/../b",
        "./local",
        "/absolute",
        "C:\\host",
        "C:/host",
        "a\\b",
        "a//b",
        "a/",
        "control\x00name",
        "control\x1fname",
        unicodedata.normalize("NFD", "café.py"),
    ],
)
def test_core_repository_file_rejects_unsafe_paths(unsafe: str) -> None:
    with pytest.raises(ValueError, match="repository file is invalid"):
        RepositoryFile(unsafe, 0, "0" * 64)


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


def test_hard_link_is_rejected_as_an_outside_content_alias(tmp_path: Path) -> None:
    outside = tmp_path.parent / "hard-link-outside-canary"
    outside.write_bytes(b"outside")
    try:
        os.link(outside, tmp_path / "inside-link")
    except OSError:
        pytest.skip("hard-link creation is unavailable")
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.LINK_UNSUPPORTED


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


def test_root_git_link_is_inspected_before_metadata_exclusion(tmp_path: Path) -> None:
    target = tmp_path.parent / "git-metadata-target"
    target.mkdir()
    git_link = tmp_path / ".git"
    try:
        git_link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.LINK_UNSUPPORTED


@pytest.mark.parametrize("metadata_kind", ["directory", "file"])
def test_root_git_metadata_is_safely_excluded(tmp_path: Path, metadata_kind: str) -> None:
    metadata = tmp_path / ".git"
    if metadata_kind == "directory":
        metadata.mkdir()
        (metadata / "config").write_bytes(b"ignored metadata")
    else:
        metadata.write_bytes(b"gitdir: ../worktree-metadata\n")
    (tmp_path / "source.py").write_bytes(b"source")
    first = _intake().inventory(tmp_path)
    second = _intake().inventory(tmp_path)
    assert first == second
    assert [item.path for item in first.files] == ["source.py"]


def test_directory_enumeration_is_bounded_before_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class EndlessEntries:
        def __init__(self) -> None:
            self.count = 0

        def __enter__(self) -> EndlessEntries:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def __iter__(self) -> EndlessEntries:
            return self

        def __next__(self) -> object:
            self.count += 1
            if self.count > 5:
                raise AssertionError("enumeration consumed beyond closed budget")
            return type("Entry", (), {"name": f"entry-{self.count}"})()

    produced = EndlessEntries()
    monkeypatch.setattr(os, "scandir", lambda _: produced)
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake(max_files=1, max_directories=1).inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.ENTRY_LIMIT
    assert produced.count == 4


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative race oracle")
def test_directory_swap_cannot_enumerate_outside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "inside").write_bytes(b"inside")
    outside = tmp_path.parent / "outside-tree"
    outside.mkdir()
    (outside / "outside-canary").write_bytes(b"outside")
    original_scandir = os.scandir
    swapped = False

    def swapping_scandir(path: int | str | bytes | os.PathLike[str]) -> object:
        nonlocal swapped
        if not swapped and isinstance(path, (str, os.PathLike)) and Path(path) == nested:
            swapped = True
            nested.rename(tmp_path / "detached")
            nested.symlink_to(outside, target_is_directory=True)
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", swapping_scandir)
    inventory = _intake().inventory(tmp_path)
    assert [item.path for item in inventory.files] == ["nested/inside"]
    assert swapped is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative race oracle")
def test_file_replacement_during_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"original")
    original_read = os.read
    replaced = False

    def replacing_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, size)
        if chunk and not replaced:
            replaced = True
            source.rename(tmp_path.parent / f"{tmp_path.name}-detached.py")
            source.write_bytes(b"replaced")
        return chunk

    monkeypatch.setattr(os, "read", replacing_read)
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.CONTENT_CHANGED
    assert replaced


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor binding oracle")
def test_child_directory_replacement_after_traversal_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "source.py").write_bytes(b"original")
    original_scandir = os.scandir
    descriptor_scans = 0
    replaced = False

    def replacing_scandir(path: int | str | bytes | os.PathLike[str]) -> object:
        nonlocal descriptor_scans, replaced
        if isinstance(path, int):
            descriptor_scans += 1
            if descriptor_scans == 3:
                nested.rename(tmp_path.parent / f"{tmp_path.name}-detached")
                nested.mkdir()
                (nested / "source.py").write_bytes(b"replacement")
                replaced = True
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", replacing_scandir)
    with pytest.raises(RepositoryIntakeError) as raised:
        _intake().inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.CONTENT_CHANGED
    assert replaced


@pytest.mark.skipif(os.name == "nt", reason="POSIX concurrent-write oracle")
def test_same_size_mutation_with_restored_metadata_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.py"
    source.write_bytes(b"original")
    original_state = source.stat()
    writer = os.open(source, os.O_RDWR)
    original_read = os.read
    end_of_passes = 0

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal end_of_passes
        chunk = original_read(descriptor, size)
        if not chunk:
            end_of_passes += 1
            if end_of_passes == 1:
                os.lseek(writer, 0, os.SEEK_SET)
                os.write(writer, b"modified")
                os.utime(
                    source,
                    ns=(original_state.st_atime_ns, original_state.st_mtime_ns),
                )
        return chunk

    monkeypatch.setattr(os, "read", mutating_read)
    try:
        with pytest.raises(RepositoryIntakeError) as raised:
            _intake().inventory(tmp_path)
    finally:
        os.close(writer)
    assert raised.value.code is RepositoryIntakeErrorCode.CONTENT_CHANGED
    assert end_of_passes >= 1


@pytest.mark.skipif(os.name != "nt", reason="Windows replacement-lock oracle")
def test_windows_directory_and_file_bindings_deny_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    source = nested / "source.py"
    source.write_bytes(b"stable")
    original_scandir = os.scandir
    original_read = os.read
    directory_lock_observed = False
    file_lock_observed = False

    def locked_scandir(path: int | str | bytes | os.PathLike[str]) -> object:
        nonlocal directory_lock_observed
        if not directory_lock_observed and path == nested:
            with pytest.raises(PermissionError):
                nested.rename(tmp_path / "renamed")
            directory_lock_observed = True
        return original_scandir(path)

    def locked_read(descriptor: int, size: int) -> bytes:
        nonlocal file_lock_observed
        chunk = original_read(descriptor, size)
        if chunk and not file_lock_observed:
            with pytest.raises(PermissionError):
                source.rename(nested / "renamed.py")
            with pytest.raises(PermissionError):
                source.write_bytes(b"mutate")
            file_lock_observed = True
        return chunk

    monkeypatch.setattr(os, "scandir", locked_scandir)
    monkeypatch.setattr(os, "read", locked_read)
    inventory = _intake().inventory(tmp_path)
    assert [item.path for item in inventory.files] == ["nested/source.py"]
    assert directory_lock_observed
    assert file_lock_observed


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
    with pytest.raises(ValueError, match="inventory limits are invalid"):
        InventoryLimits(2, 2, 257, 64, 64, 128)


def test_intake_snapshots_limits_against_retained_object_mutation(tmp_path: Path) -> None:
    limits = InventoryLimits(1, 2, 2, 64, 64, 128)
    intake = FileSystemRepositoryIntake(limits)
    object.__setattr__(limits, "max_files", 100)
    (tmp_path / "one").write_bytes(b"1")
    (tmp_path / "two").write_bytes(b"2")
    with pytest.raises(RepositoryIntakeError) as raised:
        intake.inventory(tmp_path)
    assert raised.value.code is RepositoryIntakeErrorCode.FILE_LIMIT
