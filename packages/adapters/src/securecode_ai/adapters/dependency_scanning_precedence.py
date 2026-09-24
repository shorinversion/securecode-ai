"""Deterministic lock authority over paired dependency declaration manifests."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from securecode_ai.core import DependencyManifestEntry, DependencyManifestKind

from .dependency_scanning import DependencyScanError, DependencyScanErrorCode

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
_PYPI_URLS = frozenset({"https://pypi.org/simple", "https://pypi.org/simple/"})
_GO_WORK_VERSION = re.compile(r"go[ \t]+[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
_GO_WORK_TOOLCHAIN = re.compile(r"toolchain[ \t]+go[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
_GO_WORK_USE = re.compile(r"(?:\./)?[A-Za-z0-9._/-]+\Z")
_GO_WORK_SUM = re.compile(
    r"[A-Za-z0-9.!~+/_-]+[ \t]+v[0-9A-Za-z.+-]+(?:/go\.mod)?"
    r"[ \t]+h1:[A-Za-z0-9+/]{43}=\Z"
)
_LOCK_KINDS = frozenset(
    {
        DependencyManifestKind.PIPFILE_LOCK,
        DependencyManifestKind.POETRY_LOCK,
        DependencyManifestKind.UV_LOCK,
        DependencyManifestKind.PDM_LOCK,
        DependencyManifestKind.PACKAGE_LOCK,
        DependencyManifestKind.YARN_LOCK,
        DependencyManifestKind.PNPM_LOCK,
        DependencyManifestKind.NPM_SHRINKWRAP,
        DependencyManifestKind.BUN_LOCK,
        DependencyManifestKind.GO_MOD,
        DependencyManifestKind.GO_WORK,
    }
)


@dataclass(frozen=True, slots=True)
class DependencyManifestBinding:
    manifest_path: str
    manifest_sha256: str
    authority_path: str
    authority_sha256: str


def dependency_manifest_plan(
    manifests: tuple[DependencyManifestEntry, ...],
    contents: Mapping[str, bytes],
) -> tuple[tuple[DependencyManifestEntry, ...], tuple[DependencyManifestBinding, ...]]:
    """Bind every manifest to itself or one exact paired lock."""

    if (
        type(manifests) is not tuple
        or any(type(item) is not DependencyManifestEntry for item in manifests)
        or not isinstance(contents, Mapping)
    ):
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    by_path = {item.path: item for item in manifests}
    if len(by_path) != len(manifests) or set(by_path) != set(contents):
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    covered: dict[str, DependencyManifestEntry] = {}
    workspaces = tuple(
        item for item in manifests if item.kind is DependencyManifestKind.GO_WORK
    )
    workspace_sums = tuple(
        item for item in manifests if item.kind is DependencyManifestKind.GO_WORK_SUM
    )
    if len(workspaces) > 1 or len(workspace_sums) > 1 or (workspace_sums and not workspaces):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if workspaces:
        workspace = workspaces[0]
        source = contents.get(workspace.path)
        if type(source) is not bytes:
            raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
        module_paths = _go_workspace_modules(source, workspace.path)
        go_mod_paths = {
            item.path for item in manifests if item.kind is DependencyManifestKind.GO_MOD
        }
        if not module_paths or not module_paths.issubset(go_mod_paths):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        covered[workspace.path] = workspace
        if workspace_sums:
            workspace_sum = workspace_sums[0]
            expected_sum = _join(
                workspace.path.rsplit("/", 1)[0] if "/" in workspace.path else "",
                "go.work.sum",
            )
            if workspace_sum.path != expected_sum:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            _validate_go_workspace_sum(contents.get(workspace_sum.path))
            covered[workspace_sum.path] = workspace
    for lock in manifests:
        if lock.kind in {DependencyManifestKind.GO_WORK, DependencyManifestKind.GO_WORK_SUM}:
            continue
        if lock.kind not in _LOCK_KINDS:
            continue
        source = contents.get(lock.path)
        if type(source) is not bytes:
            raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
        for path in _covered_paths(lock, source, contents):
            declaration = by_path.get(path)
            if declaration is None or not _paired(lock.kind, declaration.kind):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            if path in covered:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            covered[path] = lock
    scanned = tuple(item for item in manifests if item.path not in covered)
    bindings = tuple(
        DependencyManifestBinding(
            item.path,
            item.content_sha256,
            covered.get(item.path, item).path,
            covered.get(item.path, item).content_sha256,
        )
        for item in manifests
    )
    return scanned, bindings


def _covered_paths(
    lock: DependencyManifestEntry,
    source: bytes,
    contents: Mapping[str, bytes],
) -> tuple[str, ...]:
    directory = lock.path.rsplit("/", 1)[0] if "/" in lock.path else ""
    if lock.kind in {
        DependencyManifestKind.PACKAGE_LOCK,
        DependencyManifestKind.YARN_LOCK,
        DependencyManifestKind.PNPM_LOCK,
        DependencyManifestKind.NPM_SHRINKWRAP,
        DependencyManifestKind.BUN_LOCK,
    }:
        if lock.kind in {
            DependencyManifestKind.PACKAGE_LOCK,
            DependencyManifestKind.NPM_SHRINKWRAP,
        }:
            document = _closed_json_document(source)
            version = document.get("lockfileVersion")
            if type(version) is not int or version not in {1, 2, 3}:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        path = _join(directory, "package.json")
        return (path,) if path in contents else ()
    if lock.kind is DependencyManifestKind.GO_MOD:
        path = _join(directory, "go.sum")
        if path in contents:
            _validate_go_workspace_sum(contents.get(path))
            return (path,)
        return ()
    if lock.kind is DependencyManifestKind.PIPFILE_LOCK:
        _closed_json(source)
        path = _join(directory, "Pipfile")
        if path in contents:
            _require_pypi_source(_toml(_required_source(contents, path)).get("source"))
        return (path,) if path in contents else ()
    document = _toml(source)
    if lock.kind is DependencyManifestKind.UV_LOCK:
        return _uv_declarations(document, contents, directory)
    if lock.kind is DependencyManifestKind.POETRY_LOCK:
        path = _join(directory, "pyproject.toml")
        if path not in contents:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        declaration = _toml(_required_source(contents, path))
        tool = declaration.get("tool")
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        if not isinstance(poetry, dict):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if poetry.get("source") not in (None, [], {}):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return (path,)
    path = _join(directory, "pyproject.toml")
    if path not in contents:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    declaration = _toml(_required_source(contents, path))
    tool = declaration.get("tool")
    pdm = tool.get("pdm") if isinstance(tool, dict) else None
    if not isinstance(pdm, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if pdm.get("source") not in (None, [], {}):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return (path,)


def _go_workspace_modules(source: bytes, path: str) -> set[str]:
    if len(source) > 1_048_576 or source.startswith(b"\xef\xbb\xbf"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    directory = path.rsplit("/", 1)[0] if "/" in path else ""
    modules: set[str] = set()
    in_use_block = False
    has_go_version = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if in_use_block:
            if line == ")":
                in_use_block = False
                continue
            use_path = line
        elif line == "use (":
            in_use_block = True
            continue
        elif line.startswith("use "):
            use_path = line[4:].strip()
        elif _GO_WORK_VERSION.fullmatch(line):
            if has_go_version:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            has_go_version = True
            continue
        elif _GO_WORK_TOOLCHAIN.fullmatch(line):
            continue
        elif line.startswith("replace "):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        else:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if (
            not _GO_WORK_USE.fullmatch(use_path)
            or "\\" in use_path
            or any(part in {"", ".."} for part in use_path.removeprefix("./").split("/"))
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        relative = use_path.removeprefix("./")
        module_dir = "" if relative == "." else relative
        module_path = _join(directory, f"{module_dir}/go.mod" if module_dir else "go.mod")
        if module_path in modules:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        modules.add(module_path)
    if in_use_block or not has_go_version:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return modules


def _validate_go_workspace_sum(source: object) -> None:
    if type(source) is not bytes or len(source) > 1_048_576:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    try:
        text = source.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    for line in text.splitlines():
        if not _GO_WORK_SUM.fullmatch(line):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _uv_declarations(
    document: dict[str, object], contents: Mapping[str, bytes], directory: str
) -> tuple[str, ...]:
    manifest = document.get("manifest")
    packages = document.get("package")
    if not isinstance(manifest, dict) or not isinstance(packages, list):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    members_value = manifest.get("members")
    if not isinstance(members_value, list) or any(
        not isinstance(item, str) for item in members_value
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    members = {_canonical_name(item) for item in members_value}
    if len(members) != len(members_value):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    paths = []
    for package in packages:
        if not isinstance(package, dict):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        source = package.get("source")
        if not isinstance(source, dict) or len(source) != 1:
            continue
        origin = next(iter(source))
        if origin not in {"editable", "virtual"}:
            continue
        name = package.get("name")
        relative = source[origin]
        if (
            not isinstance(name, str)
            or _NAME.fullmatch(name) is None
            or _canonical_name(name) not in members
            or not isinstance(relative, str)
            or not _relative_path(relative)
            or (origin == "virtual" and relative != ".")
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        path = _workspace_declaration_path(directory, relative)
        declaration = _toml(_required_source(contents, path))
        project = declaration.get("project")
        if not isinstance(project, dict) or _canonical_name(project.get("name")) != _canonical_name(
            name
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        _validate_uv_declaration_origin(declaration, members)
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return tuple(sorted(paths))


def _validate_uv_declaration_origin(
    declaration: dict[str, object], workspace_members: set[str]
) -> None:
    tool = declaration.get("tool", {})
    if not isinstance(tool, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    uv = tool.get("uv", {})
    if not isinstance(uv, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    index = uv.get("index")
    if index is not None and not (
        isinstance(index, list)
        and len(index) == 1
        and isinstance(index[0], dict)
        and set(index[0]) == {"default", "name", "url"}
        and index[0].get("default") is True
        and index[0].get("url") in _PYPI_URLS
        and isinstance(index[0].get("name"), str)
        and _NAME.fullmatch(index[0]["name"]) is not None
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for key in ("default-index", "index-url"):
        if key in uv and uv[key] not in _PYPI_URLS:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if any(key in uv for key in ("extra-index-url", "find-links", "no-index")):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    sources = uv.get("sources", {})
    if not isinstance(sources, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for name, source in sources.items():
        if (
            not isinstance(name, str)
            or _canonical_name(name) not in workspace_members
            or not isinstance(source, dict)
            or source != {"workspace": True}
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _require_pypi_source(value: object) -> None:
    if not isinstance(value, list) or len(value) != 1:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    source = value[0]
    if (
        not isinstance(source, dict)
        or set(source) != {"name", "url", "verify_ssl"}
        or not isinstance(source.get("name"), str)
        or _NAME.fullmatch(source["name"]) is None
        or source.get("url") not in _PYPI_URLS
        or source.get("verify_ssl") is not True
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _paired(lock: DependencyManifestKind, declaration: DependencyManifestKind) -> bool:
    if lock is DependencyManifestKind.PIPFILE_LOCK:
        return declaration is DependencyManifestKind.PIPFILE
    if lock in {
        DependencyManifestKind.PACKAGE_LOCK,
        DependencyManifestKind.YARN_LOCK,
        DependencyManifestKind.PNPM_LOCK,
        DependencyManifestKind.NPM_SHRINKWRAP,
        DependencyManifestKind.BUN_LOCK,
    }:
        return declaration is DependencyManifestKind.PACKAGE_JSON
    if lock is DependencyManifestKind.GO_MOD:
        return declaration is DependencyManifestKind.GO_SUM
    return declaration is DependencyManifestKind.PYPROJECT


def _required_source(contents: Mapping[str, bytes], path: str) -> bytes:
    source = contents.get(path)
    if type(source) is not bytes:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return source


def _toml(source: bytes) -> dict[str, object]:
    try:
        return tomllib.loads(source.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None


def _closed_json(source: bytes) -> None:
    _closed_json_document(source)


def _closed_json_document(source: bytes) -> dict[str, object]:
    try:
        value = json.loads(source.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    if not isinstance(value, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return value


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _canonical_name(value: object) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return re.sub(r"[-_.]+", "-", value).lower()


def _relative_path(value: str) -> bool:
    if value == ".":
        return True
    path = PurePosixPath(value)
    return bool(
        value
        and len(value.encode("utf-8")) <= 1024
        and "\\" not in value
        and not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".."} for part in path.parts)
        and not path.parts[0].endswith(":")
    )


def _workspace_declaration_path(directory: str, relative: str) -> str:
    if directory and not _relative_path(directory):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    member = "pyproject.toml" if relative == "." else f"{relative}/pyproject.toml"
    path = _join(directory, member)
    if not _relative_path(path):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return path


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


__all__ = ["DependencyManifestBinding", "dependency_manifest_plan"]
