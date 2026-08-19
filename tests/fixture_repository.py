"""Hermetic builder for the checked-in opaque demonstration repositories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum, unique
from pathlib import Path
from typing import Final, cast, final

_REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
_TEMPLATE_ROOT: Final = _REPOSITORY_ROOT / "examples" / "demo-repositories"
_CATALOG_PATH: Final = _TEMPLATE_ROOT / "catalog.json"
_CATALOG_VERSION: Final = "securecode.fixture-catalog.v1"
_TREE_VERSION: Final = "securecode.fixture-tree.v1"
_CONTENT_AUTHORITY: Final = "NONE"
_LOGICAL_MODE: Final = "100644"
_EXPECTED_PATHS: Final = ("README.md", "app.py")
_MAX_CATALOG_BYTES: Final = 131_072
_MAX_FILE_BYTES: Final = 65_536
_HASH_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_CONCRETE_PATH_TYPE: Final = type(Path())
_SOURCE_DATASET: Final = {
    "dataset_id": "SC-MVP-CWE89",
    "license": "CC0-1.0",
    "revision": "securecode-spec-0.2.0",
    "sha256": "436843b02bee53cc2997903b3e61afb9734ff5fa2580756ecba7344e92c12663",
    "version": "1.1.0",
}


@unique
class FixtureId(StrEnum):
    """Closed opaque fixture identifiers."""

    REPO_001 = "repo-001"
    REPO_002 = "repo-002"
    REPO_003 = "repo-003"
    REPO_004 = "repo-004"
    REPO_005 = "repo-005"
    REPO_006 = "repo-006"


@unique
class FixtureRepositoryErrorCode(StrEnum):
    """Stable, non-sensitive factory failure reasons."""

    INVALID_FIXTURE_ID = "INVALID_FIXTURE_ID"
    CATALOG_IO_ERROR = "CATALOG_IO_ERROR"
    CATALOG_INVALID = "CATALOG_INVALID"
    CATALOG_NONCANONICAL = "CATALOG_NONCANONICAL"
    TEMPLATE_INVALID = "TEMPLATE_INVALID"
    TEMPLATE_MISMATCH = "TEMPLATE_MISMATCH"
    DESTINATION_PARENT_INVALID = "DESTINATION_PARENT_INVALID"
    DESTINATION_EXISTS = "DESTINATION_EXISTS"
    BUILD_IO_ERROR = "BUILD_IO_ERROR"
    CLEANUP_CONFLICT = "CLEANUP_CONFLICT"


_SAFE_MESSAGES: Final = {
    FixtureRepositoryErrorCode.INVALID_FIXTURE_ID: "fixture identifier is invalid",
    FixtureRepositoryErrorCode.CATALOG_IO_ERROR: "fixture catalog could not be read",
    FixtureRepositoryErrorCode.CATALOG_INVALID: "fixture catalog is invalid",
    FixtureRepositoryErrorCode.CATALOG_NONCANONICAL: "fixture catalog is not canonical",
    FixtureRepositoryErrorCode.TEMPLATE_INVALID: "fixture template is invalid",
    FixtureRepositoryErrorCode.TEMPLATE_MISMATCH: "fixture template does not match catalog",
    FixtureRepositoryErrorCode.DESTINATION_PARENT_INVALID: "destination parent is invalid",
    FixtureRepositoryErrorCode.DESTINATION_EXISTS: "destination already exists",
    FixtureRepositoryErrorCode.BUILD_IO_ERROR: "fixture repository could not be built",
    FixtureRepositoryErrorCode.CLEANUP_CONFLICT: "fixture cleanup was stopped safely",
}


@final
class FixtureRepositoryError(RuntimeError):
    """A fixed-message factory failure that never carries source or path data."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: FixtureRepositoryErrorCode) -> None:
        self.code = code
        self.safe_message = _SAFE_MESSAGES[code]
        super().__init__(self.safe_message)

    def __repr__(self) -> str:
        return (
            f"FixtureRepositoryError(code={self.code.value!r}, safe_message={self.safe_message!r})"
        )


@dataclass(frozen=True, slots=True)
class BuiltFixtureFile:
    """One immutable file record in a built repository."""

    path: str
    mode: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class BuiltFixture:
    """Trusted out-of-band metadata for one completed fixture build."""

    fixture_id: FixtureId
    destination: Path
    instruction_authority: str
    tree_sha256: str
    files: tuple[BuiltFixtureFile, ...]


@dataclass(frozen=True, slots=True)
class _CatalogFixture:
    fixture_id: FixtureId
    tree_sha256: str
    files: tuple[BuiltFixtureFile, ...]


@dataclass(frozen=True, slots=True)
class _Catalog:
    fixtures: tuple[_CatalogFixture, ...]


@dataclass(frozen=True, slots=True)
class _OwnedFile:
    path: Path
    device: int
    inode: int


@final
class _WriteFailure(RuntimeError):
    __slots__ = ("owned_file",)

    def __init__(self, owned_file: _OwnedFile | None) -> None:
        self.owned_file = owned_file
        super().__init__()


class _DuplicateJsonKey(ValueError):
    pass


def _error(code: FixtureRepositoryErrorCode) -> FixtureRepositoryError:
    return FixtureRepositoryError(code)


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise ValueError


def _canonical_json_bytes(value: object, *, terminal_lf: bool) -> bytes:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if terminal_lf:
        rendered += "\n"
    return rendered.encode("utf-8")


def _as_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError
    result = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in result):
        raise ValueError
    typed = cast(dict[str, object], result)
    if frozenset(typed) != keys:
        raise ValueError
    return typed


def _as_list(value: object, length: int) -> list[object]:
    if not isinstance(value, list) or len(value) != length:
        raise ValueError
    return cast(list[object], value)


def _as_string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError
    return value


def _as_size(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_FILE_BYTES:
        raise ValueError
    return value


def _as_hash(value: object) -> str:
    result = _as_string(value)
    if _HASH_PATTERN.fullmatch(result) is None:
        raise ValueError
    return result


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _read_regular_file(path: Path, maximum: int, code: FixtureRepositoryErrorCode) -> bytes:
    descriptor = -1
    failed = False
    data = b""
    try:
        if _is_link_like(path):
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise OSError
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if len(data) > maximum or identity_before != identity_after or len(data) != before.st_size:
            raise OSError
    except Exception:
        failed = True
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    if failed:
        raise _error(code)
    return data


def _validate_catalog_file(value: object) -> BuiltFixtureFile:
    item = _as_object(value, frozenset({"mode", "path", "sha256", "size_bytes"}))
    path = _as_string(item["path"])
    if path not in _EXPECTED_PATHS:
        raise ValueError
    if _as_string(item["mode"]) != _LOGICAL_MODE:
        raise ValueError
    return BuiltFixtureFile(
        path=path,
        mode=_LOGICAL_MODE,
        size_bytes=_as_size(item["size_bytes"]),
        sha256=_as_hash(item["sha256"]),
    )


def _validate_catalog(raw_object: object) -> _Catalog:
    root = _as_object(
        raw_object,
        frozenset({"fixtures", "repository_content_authority", "schema_version", "source_dataset"}),
    )
    if _as_string(root["schema_version"]) != _CATALOG_VERSION:
        raise ValueError
    if _as_string(root["repository_content_authority"]) != _CONTENT_AUTHORITY:
        raise ValueError
    source = _as_object(root["source_dataset"], frozenset(_SOURCE_DATASET))
    if any(_as_string(source[key]) != expected for key, expected in _SOURCE_DATASET.items()):
        raise ValueError

    fixture_values = _as_list(root["fixtures"], len(FixtureId))
    fixtures: list[_CatalogFixture] = []
    expected_ids = tuple(FixtureId)
    for position, value in enumerate(fixture_values):
        item = _as_object(value, frozenset({"files", "fixture_id", "tree_sha256"}))
        fixture_id = FixtureId(_as_string(item["fixture_id"]))
        if fixture_id is not expected_ids[position]:
            raise ValueError
        file_values = _as_list(item["files"], len(_EXPECTED_PATHS))
        files = tuple(_validate_catalog_file(file_value) for file_value in file_values)
        if tuple(file.path for file in files) != _EXPECTED_PATHS:
            raise ValueError
        if len({file.path.casefold() for file in files}) != len(files):
            raise ValueError
        fixtures.append(
            _CatalogFixture(
                fixture_id=fixture_id,
                tree_sha256=_as_hash(item["tree_sha256"]),
                files=files,
            )
        )
    return _Catalog(tuple(fixtures))


def _load_catalog() -> _Catalog:
    raw = _read_regular_file(
        _CATALOG_PATH, _MAX_CATALOG_BYTES, FixtureRepositoryErrorCode.CATALOG_IO_ERROR
    )
    invalid = False
    raw_object: object | None = None
    catalog: _Catalog | None = None
    try:
        raw_object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_constant=_reject_constant,
        )
        catalog = _validate_catalog(raw_object)
    except Exception:
        invalid = True
    if invalid or raw_object is None or catalog is None:
        raise _error(FixtureRepositoryErrorCode.CATALOG_INVALID)
    if raw != _canonical_json_bytes(raw_object, terminal_lf=True):
        raise _error(FixtureRepositoryErrorCode.CATALOG_NONCANONICAL)
    return catalog


def _catalog_fixture(catalog: _Catalog, fixture_id: FixtureId) -> _CatalogFixture:
    for fixture in catalog.fixtures:
        if fixture.fixture_id is fixture_id:
            return fixture
    raise _error(FixtureRepositoryErrorCode.CATALOG_INVALID)


def _tree_hash(files: tuple[BuiltFixtureFile, ...]) -> str:
    value = {
        "schema_version": _TREE_VERSION,
        "files": [
            {
                "mode": item.mode,
                "path": item.path,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
            }
            for item in files
        ],
    }
    return hashlib.sha256(_canonical_json_bytes(value, terminal_lf=False)).hexdigest()


def _validated_template(fixture: _CatalogFixture) -> tuple[bytes, ...]:
    directory = _TEMPLATE_ROOT / fixture.fixture_id.value
    invalid = False
    try:
        if _is_link_like(_TEMPLATE_ROOT) or _is_link_like(directory) or not directory.is_dir():
            raise OSError
        with os.scandir(directory) as entries:
            names = tuple(sorted((entry.name for entry in entries), key=lambda name: name.encode()))
        if names != tuple(sorted(_EXPECTED_PATHS, key=lambda name: name.encode())):
            raise OSError
        if len({name.casefold() for name in names}) != len(names):
            raise OSError
    except Exception:
        invalid = True
    if invalid:
        raise _error(FixtureRepositoryErrorCode.TEMPLATE_INVALID)

    contents: list[bytes] = []
    actual_records: list[BuiltFixtureFile] = []
    for expected in fixture.files:
        try:
            data = _read_regular_file(
                directory / expected.path,
                _MAX_FILE_BYTES,
                FixtureRepositoryErrorCode.TEMPLATE_INVALID,
            )
        except FixtureRepositoryError:
            raise
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != expected.size_bytes or digest != expected.sha256:
            raise _error(FixtureRepositoryErrorCode.TEMPLATE_MISMATCH)
        contents.append(data)
        actual_records.append(BuiltFixtureFile(expected.path, expected.mode, len(data), digest))
    records = tuple(actual_records)
    if _tree_hash(records) != fixture.tree_sha256:
        raise _error(FixtureRepositoryErrorCode.TEMPLATE_MISMATCH)
    return tuple(contents)


def _directory_identity(path: Path) -> tuple[int, int]:
    details = os.lstat(path)
    if not stat.S_ISDIR(details.st_mode) or _is_link_like(path):
        raise OSError
    return (details.st_dev, details.st_ino)


def _cleanup_reservation(
    destination: Path,
    identity: tuple[int, int],
    owned_files: tuple[_OwnedFile, ...],
) -> bool:
    try:
        if _directory_identity(destination) != identity:
            return False
        with os.scandir(destination) as entries:
            names = {entry.name for entry in entries}
        owned_names = {item.path.name for item in owned_files}
        if not names.issubset(owned_names):
            return False
        for item in reversed(owned_files):
            if item.path.name not in names:
                continue
            details = os.lstat(item.path)
            if (
                not stat.S_ISREG(details.st_mode)
                or _is_link_like(item.path)
                or (details.st_dev, details.st_ino) != (item.device, item.inode)
            ):
                return False
            item.path.unlink()
        destination.rmdir()
        return True
    except Exception:
        return False


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError
        offset += written


def _write_fixture_file(path: Path, data: bytes) -> _OwnedFile:
    descriptor = -1
    owned_file: _OwnedFile | None = None
    failed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o644)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError
        owned_file = _OwnedFile(path=path, device=opened.st_dev, inode=opened.st_ino)
        if os.name == "posix":
            os.fchmod(descriptor, 0o644)  # type: ignore[attr-defined, unused-ignore]
        _write_all(descriptor, data)
        details = os.fstat(descriptor)
        if (details.st_dev, details.st_ino) != (
            owned_file.device,
            owned_file.inode,
        ) or details.st_size != len(data):
            raise OSError
        if os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o644:
            raise OSError
    except Exception:
        failed = True
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception:
                failed = True
    if failed or owned_file is None:
        raise _WriteFailure(owned_file)
    return owned_file


def _destination_path(destination: Path) -> Path:
    if type(destination) is not _CONCRETE_PATH_TYPE:
        raise _error(FixtureRepositoryErrorCode.DESTINATION_PARENT_INVALID)
    failed = False
    result: Path | None = None
    try:
        result = Path(os.fspath(destination)).absolute()
    except Exception:
        failed = True
    if failed or result is None:
        raise _error(FixtureRepositoryErrorCode.DESTINATION_PARENT_INVALID)
    return result


def _validate_destination(destination: Path) -> None:
    parent = destination.parent
    parent_invalid = False
    try:
        if destination.name in {"", ".", ".."}:
            raise OSError
        if _is_link_like(parent) or not parent.is_dir():
            raise OSError
    except Exception:
        parent_invalid = True
    if parent_invalid:
        raise _error(FixtureRepositoryErrorCode.DESTINATION_PARENT_INVALID)
    exists = False
    existence_invalid = False
    try:
        exists = destination.exists() or _is_link_like(destination)
    except Exception:
        existence_invalid = True
    if existence_invalid:
        raise _error(FixtureRepositoryErrorCode.DESTINATION_PARENT_INVALID)
    if exists:
        raise _error(FixtureRepositoryErrorCode.DESTINATION_EXISTS)


def build_fixture_repository(fixture_id: FixtureId, destination: Path) -> BuiltFixture:
    """Materialize one validated fixture without reading evaluator expectations."""

    if not isinstance(fixture_id, FixtureId):
        raise _error(FixtureRepositoryErrorCode.INVALID_FIXTURE_ID)

    catalog = _load_catalog()
    fixture = _catalog_fixture(catalog, fixture_id)
    contents = _validated_template(fixture)
    target = _destination_path(destination)
    _validate_destination(target)

    reservation_error: FixtureRepositoryErrorCode | None = None
    try:
        target.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError:
        reservation_error = FixtureRepositoryErrorCode.DESTINATION_EXISTS
    except Exception:
        reservation_error = FixtureRepositoryErrorCode.BUILD_IO_ERROR
    if reservation_error is not None:
        raise _error(reservation_error)

    owned_files: list[_OwnedFile] = []
    identity: tuple[int, int] | None = None
    build_failed = False
    try:
        identity = _directory_identity(target)
        for record, data in zip(fixture.files, contents, strict=True):
            output = target / record.path
            owned_files.append(_write_fixture_file(output, data))
    except _WriteFailure as error:
        if error.owned_file is not None:
            owned_files.append(error.owned_file)
        build_failed = True
    except Exception:
        build_failed = True
    if build_failed:
        if identity is None:
            identity_failed = False
            try:
                identity = _directory_identity(target)
            except Exception:
                identity_failed = True
            if identity_failed or identity is None:
                raise _error(FixtureRepositoryErrorCode.CLEANUP_CONFLICT)
        if not _cleanup_reservation(target, identity, tuple(owned_files)):
            raise _error(FixtureRepositoryErrorCode.CLEANUP_CONFLICT)
        raise _error(FixtureRepositoryErrorCode.BUILD_IO_ERROR)

    return BuiltFixture(
        fixture_id=fixture_id,
        destination=target,
        instruction_authority=_CONTENT_AUTHORITY,
        tree_sha256=fixture.tree_sha256,
        files=fixture.files,
    )
