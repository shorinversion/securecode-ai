"""Deterministic repository metadata discovery over an admitted inventory."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

from .repository import RepositoryFile, repository_tree_sha256

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RULE_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SUFFIX = re.compile(r"\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
_REQUIREMENTS_FILE = re.compile(r"requirements(?:[-_.][A-Za-z0-9._-]+)?\.txt\Z")
_MAX_RULES = 256
_MAX_RULE_PATH_BYTES = 4096
_MAX_RULE_DEPTH = 256
_MAX_RULE_COMPONENT_BYTES = 255
_MAX_DISCOVERY_FILES = 100_000


class DiscoveryErrorCode(StrEnum):
    POLICY_INVALID = "POLICY_INVALID"
    INVENTORY_LIMIT = "INVENTORY_LIMIT"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    POLICY_MISMATCH = "POLICY_MISMATCH"


class DiscoveryError(RuntimeError):
    """Fixed, non-echoing discovery failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: DiscoveryErrorCode) -> None:
        if type(code) is not DiscoveryErrorCode:
            raise TypeError("discovery error code is invalid")
        self.code = code
        self.safe_message = "repository discovery failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class IgnoreRuleKind(StrEnum):
    PATH = "path"
    SUBTREE = "subtree"
    SUFFIX = "suffix"


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    rule_id: str
    kind: IgnoreRuleKind
    value: str

    def __post_init__(self) -> None:
        if (
            type(self.rule_id) is not str
            or not _RULE_ID.fullmatch(self.rule_id)
            or type(self.kind) is not IgnoreRuleKind
            or type(self.value) is not str
        ):
            raise ValueError("ignore rule is invalid")
        if self.kind is IgnoreRuleKind.SUFFIX:
            valid = _SUFFIX.fullmatch(self.value) is not None
        else:
            valid = _valid_rule_path(self.value)
        if not valid:
            raise ValueError("ignore rule is invalid")

    def matches(self, path: str) -> bool:
        if self.kind is IgnoreRuleKind.PATH:
            return path == self.value
        if self.kind is IgnoreRuleKind.SUBTREE:
            return path == self.value or path.startswith(f"{self.value}/")
        return path.endswith(self.value)


def _valid_relative_path(path: str) -> bool:
    if type(path) is not str:
        return False
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    parts = path.split("/")
    return bool(
        path
        and not path.startswith("/")
        and "\\" not in path
        and not (
            len(parts[0]) >= 2
            and parts[0][0].isascii()
            and parts[0][0].isalpha()
            and parts[0][1] == ":"
        )
        and all(
            part and part not in {".", ".."} and unicodedata.normalize("NFC", part) == part
            for part in parts
        )
        and not any(ord(character) < 32 or ord(character) == 127 for character in path)
    )


def _valid_rule_path(path: str) -> bool:
    if not _valid_relative_path(path):
        return False
    parts = path.split("/")
    return bool(
        len(parts) <= _MAX_RULE_DEPTH
        and len(path.encode("utf-8")) <= _MAX_RULE_PATH_BYTES
        and all(len(part.encode("utf-8")) <= _MAX_RULE_COMPONENT_BYTES for part in parts)
    )


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class IgnorePolicy:
    policy_id: str
    policy_version: str
    rules: tuple[IgnoreRule, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.policy_id) is not str
            or not _RULE_ID.fullmatch(self.policy_id)
            or type(self.policy_version) is not str
            or not self.policy_version
            or len(self.policy_version) > 64
            or type(self.rules) is not tuple
            or len(self.rules) > _MAX_RULES
            or any(type(rule) is not IgnoreRule for rule in self.rules)
        ):
            raise ValueError("ignore policy is invalid")
        ids = tuple(rule.rule_id for rule in self.rules)
        collision_keys = tuple(
            (
                "suffix" if rule.kind is IgnoreRuleKind.SUFFIX else "path",
                rule.value.casefold(),
            )
            for rule in self.rules
        )
        if len(ids) != len(set(ids)) or len(collision_keys) != len(set(collision_keys)):
            raise ValueError("ignore policy is invalid")

    @property
    def content_sha256(self) -> str:
        return _canonical_hash(
            {
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "rules": [
                    {"kind": rule.kind.value, "rule_id": rule.rule_id, "value": rule.value}
                    for rule in self.rules
                ],
            }
        )

    def matching_rule(self, path: str) -> IgnoreRule | None:
        for rule in self.rules:
            if rule.matches(path):
                return rule
        return None


class LanguageId(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"


class LanguageSupport(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


_LANGUAGE_BY_SUFFIX = {
    ".py": LanguageId.PYTHON,
    ".pyi": LanguageId.PYTHON,
    ".js": LanguageId.JAVASCRIPT,
    ".jsx": LanguageId.JAVASCRIPT,
    ".mjs": LanguageId.JAVASCRIPT,
    ".cjs": LanguageId.JAVASCRIPT,
    ".ts": LanguageId.TYPESCRIPT,
    ".tsx": LanguageId.TYPESCRIPT,
    ".mts": LanguageId.TYPESCRIPT,
    ".cts": LanguageId.TYPESCRIPT,
    ".go": LanguageId.GO,
}


def _language_for(path: str) -> LanguageId | None:
    name = path.rsplit("/", 1)[-1].casefold()
    for suffix in sorted(_LANGUAGE_BY_SUFFIX, key=len, reverse=True):
        if name.endswith(suffix):
            return _LANGUAGE_BY_SUFFIX[suffix]
    return None


@dataclass(frozen=True, slots=True)
class DiscoveredLanguageFile:
    path: str
    content_sha256: str
    ignored_by_rule_id: str | None

    def __post_init__(self) -> None:
        if (
            not _valid_relative_path(self.path)
            or type(self.content_sha256) is not str
            or not _SHA256.fullmatch(self.content_sha256)
            or (
                self.ignored_by_rule_id is not None
                and (
                    type(self.ignored_by_rule_id) is not str
                    or not _RULE_ID.fullmatch(self.ignored_by_rule_id)
                )
            )
        ):
            raise ValueError("language file is invalid")


@dataclass(frozen=True, slots=True)
class LanguageManifestEntry:
    language: LanguageId
    support: LanguageSupport
    files: tuple[DiscoveredLanguageFile, ...]

    def __post_init__(self) -> None:
        expected_support = (
            LanguageSupport.SUPPORTED
            if self.language is LanguageId.PYTHON
            else LanguageSupport.UNSUPPORTED
        )
        if (
            type(self.language) is not LanguageId
            or type(self.support) is not LanguageSupport
            or self.support is not expected_support
            or type(self.files) is not tuple
            or not self.files
            or len(self.files) > _MAX_DISCOVERY_FILES
            or any(type(item) is not DiscoveredLanguageFile for item in self.files)
        ):
            raise ValueError("language manifest entry is invalid")
        paths = tuple(item.path for item in self.files)
        if (
            paths != tuple(sorted(paths))
            or len(paths) != len(set(paths))
            or any(_language_for(item.path) is not self.language for item in self.files)
        ):
            raise ValueError("language manifest entry is invalid")


class DependencyEcosystem(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"


class DependencyManifestKind(StrEnum):
    PYPROJECT = "pyproject"
    REQUIREMENTS = "requirements"
    PIPFILE = "pipfile"
    PIPFILE_LOCK = "pipfile_lock"
    POETRY_LOCK = "poetry_lock"
    UV_LOCK = "uv_lock"
    PDM_LOCK = "pdm_lock"
    SETUP_PY = "setup_py"
    SETUP_CFG = "setup_cfg"
    PACKAGE_JSON = "package_json"
    PACKAGE_LOCK = "package_lock"
    YARN_LOCK = "yarn_lock"
    PNPM_LOCK = "pnpm_lock"
    NPM_SHRINKWRAP = "npm_shrinkwrap"
    BUN_LOCK = "bun_lock"
    GO_MOD = "go_mod"
    GO_SUM = "go_sum"
    GO_WORK = "go_work"
    GO_WORK_SUM = "go_work_sum"


_DEPENDENCY_FILES = {
    "pyproject.toml": (DependencyEcosystem.PYTHON, DependencyManifestKind.PYPROJECT),
    "requirements.txt": (
        DependencyEcosystem.PYTHON,
        DependencyManifestKind.REQUIREMENTS,
    ),
    "Pipfile": (DependencyEcosystem.PYTHON, DependencyManifestKind.PIPFILE),
    "Pipfile.lock": (DependencyEcosystem.PYTHON, DependencyManifestKind.PIPFILE_LOCK),
    "poetry.lock": (DependencyEcosystem.PYTHON, DependencyManifestKind.POETRY_LOCK),
    "uv.lock": (DependencyEcosystem.PYTHON, DependencyManifestKind.UV_LOCK),
    "pdm.lock": (DependencyEcosystem.PYTHON, DependencyManifestKind.PDM_LOCK),
    "setup.py": (DependencyEcosystem.PYTHON, DependencyManifestKind.SETUP_PY),
    "setup.cfg": (DependencyEcosystem.PYTHON, DependencyManifestKind.SETUP_CFG),
    "package.json": (
        DependencyEcosystem.JAVASCRIPT,
        DependencyManifestKind.PACKAGE_JSON,
    ),
    "package-lock.json": (
        DependencyEcosystem.JAVASCRIPT,
        DependencyManifestKind.PACKAGE_LOCK,
    ),
    "yarn.lock": (DependencyEcosystem.JAVASCRIPT, DependencyManifestKind.YARN_LOCK),
    "pnpm-lock.yaml": (
        DependencyEcosystem.JAVASCRIPT,
        DependencyManifestKind.PNPM_LOCK,
    ),
    "npm-shrinkwrap.json": (
        DependencyEcosystem.JAVASCRIPT,
        DependencyManifestKind.NPM_SHRINKWRAP,
    ),
    "bun.lock": (DependencyEcosystem.JAVASCRIPT, DependencyManifestKind.BUN_LOCK),
    "bun.lockb": (DependencyEcosystem.JAVASCRIPT, DependencyManifestKind.BUN_LOCK),
    "go.mod": (DependencyEcosystem.GO, DependencyManifestKind.GO_MOD),
    "go.sum": (DependencyEcosystem.GO, DependencyManifestKind.GO_SUM),
    "go.work": (DependencyEcosystem.GO, DependencyManifestKind.GO_WORK),
    "go.work.sum": (DependencyEcosystem.GO, DependencyManifestKind.GO_WORK_SUM),
}


def _dependency_for(
    path: str,
) -> tuple[DependencyEcosystem, DependencyManifestKind] | None:
    basename = path.rsplit("/", 1)[-1]
    exact = _DEPENDENCY_FILES.get(basename)
    if exact is not None:
        return exact
    if _REQUIREMENTS_FILE.fullmatch(basename):
        return DependencyEcosystem.PYTHON, DependencyManifestKind.REQUIREMENTS
    return None


@dataclass(frozen=True, slots=True)
class DependencyManifestEntry:
    path: str
    content_sha256: str
    ecosystem: DependencyEcosystem
    kind: DependencyManifestKind
    ignored_by_rule_id: str | None

    def __post_init__(self) -> None:
        expected = _dependency_for(self.path)
        if (
            not _valid_relative_path(self.path)
            or type(self.content_sha256) is not str
            or not _SHA256.fullmatch(self.content_sha256)
            or type(self.ecosystem) is not DependencyEcosystem
            or type(self.kind) is not DependencyManifestKind
            or expected != (self.ecosystem, self.kind)
            or (
                self.ignored_by_rule_id is not None
                and (
                    type(self.ignored_by_rule_id) is not str
                    or not _RULE_ID.fullmatch(self.ignored_by_rule_id)
                )
            )
        ):
            raise ValueError("dependency manifest entry is invalid")


@dataclass(frozen=True, slots=True)
class IgnoredFile:
    path: str
    size_bytes: int
    content_sha256: str
    rule_id: str

    def __post_init__(self) -> None:
        if (
            not _valid_relative_path(self.path)
            or type(self.size_bytes) is not int
            or self.size_bytes < 0
            or type(self.content_sha256) is not str
            or not _SHA256.fullmatch(self.content_sha256)
            or type(self.rule_id) is not str
            or not _RULE_ID.fullmatch(self.rule_id)
        ):
            raise ValueError("ignored file is invalid")


def _discovery_payload(
    inventory_tree_sha256: str,
    ignore_policy: IgnorePolicy,
    analyzed_files: tuple[RepositoryFile, ...],
    ignored_files: tuple[IgnoredFile, ...],
    languages: tuple[LanguageManifestEntry, ...],
    dependency_manifests: tuple[DependencyManifestEntry, ...],
) -> dict[str, object]:
    return {
        "inventory_tree_sha256": inventory_tree_sha256,
        "ignore_policy_sha256": ignore_policy.content_sha256,
        "analyzed_files": [
            {"path": item.path, "size_bytes": item.size_bytes, "sha256": item.content_sha256}
            for item in analyzed_files
        ],
        "ignored_files": [
            {
                "path": item.path,
                "size_bytes": item.size_bytes,
                "sha256": item.content_sha256,
                "rule_id": item.rule_id,
            }
            for item in ignored_files
        ],
        "languages": [
            {
                "language": entry.language.value,
                "support": entry.support.value,
                "files": [
                    {
                        "path": item.path,
                        "sha256": item.content_sha256,
                        "ignored_by_rule_id": item.ignored_by_rule_id,
                    }
                    for item in entry.files
                ],
            }
            for entry in languages
        ],
        "dependency_manifests": [
            {
                "path": item.path,
                "sha256": item.content_sha256,
                "ecosystem": item.ecosystem.value,
                "kind": item.kind.value,
                "ignored_by_rule_id": item.ignored_by_rule_id,
            }
            for item in dependency_manifests
        ],
    }


def _discovery_manifest_hash(manifest: DiscoveryManifest) -> str:
    return _canonical_hash(
        _discovery_payload(
            manifest.inventory_tree_sha256,
            manifest.ignore_policy,
            manifest.analyzed_files,
            manifest.ignored_files,
            manifest.languages,
            manifest.dependency_manifests,
        )
    )


@dataclass(frozen=True, slots=True)
class DiscoveryManifest:
    inventory_tree_sha256: str
    ignore_policy: IgnorePolicy
    analyzed_files: tuple[RepositoryFile, ...]
    ignored_files: tuple[IgnoredFile, ...]
    languages: tuple[LanguageManifestEntry, ...]
    dependency_manifests: tuple[DependencyManifestEntry, ...]
    manifest_sha256: str

    @property
    def ignore_policy_sha256(self) -> str:
        return self.ignore_policy.content_sha256

    def __post_init__(self) -> None:
        tuple_fields = (
            self.analyzed_files,
            self.ignored_files,
            self.languages,
            self.dependency_manifests,
        )
        if (
            any(
                type(value) is not str or not _SHA256.fullmatch(value)
                for value in (
                    self.inventory_tree_sha256,
                    self.manifest_sha256,
                )
            )
            or type(self.ignore_policy) is not IgnorePolicy
            or any(type(value) is not tuple for value in tuple_fields)
            or len(self.analyzed_files) + len(self.ignored_files) > _MAX_DISCOVERY_FILES
            or len(self.languages) > len(LanguageId)
            or len(self.dependency_manifests) > len(self.analyzed_files) + len(self.ignored_files)
            or any(type(item) is not RepositoryFile for item in self.analyzed_files)
            or any(type(item) is not IgnoredFile for item in self.ignored_files)
            or any(type(item) is not LanguageManifestEntry for item in self.languages)
            or any(type(item) is not DependencyManifestEntry for item in self.dependency_manifests)
        ):
            raise ValueError("discovery manifest is invalid")
        all_files: dict[str, tuple[str, str | None]] = {
            item.path: (item.content_sha256, None) for item in self.analyzed_files
        }
        if len(all_files) != len(self.analyzed_files):
            raise ValueError("discovery manifest is invalid")
        reconstructed_files = list(self.analyzed_files)
        for item in self.ignored_files:
            if item.path in all_files:
                raise ValueError("discovery manifest is invalid")
            all_files[item.path] = (item.content_sha256, item.rule_id)
            reconstructed_files.append(
                RepositoryFile(item.path, item.size_bytes, item.content_sha256)
            )
        all_paths = tuple(all_files)
        if (
            tuple(item.path for item in self.analyzed_files)
            != tuple(sorted(item.path for item in self.analyzed_files))
            or tuple(item.path for item in self.ignored_files)
            != tuple(sorted(item.path for item in self.ignored_files))
            or len(all_paths) != len(set(all_paths))
            or tuple(entry.language.value for entry in self.languages)
            != tuple(sorted(entry.language.value for entry in self.languages))
            or len({entry.language for entry in self.languages}) != len(self.languages)
            or tuple(item.path for item in self.dependency_manifests)
            != tuple(sorted(item.path for item in self.dependency_manifests))
            or sum(len(entry.files) for entry in self.languages) > _MAX_DISCOVERY_FILES
        ):
            raise ValueError("discovery manifest is invalid")
        reconstructed = tuple(sorted(reconstructed_files, key=lambda item: item.path))
        if (
            repository_tree_sha256(reconstructed) != self.inventory_tree_sha256
            or any(
                self.ignore_policy.matching_rule(item.path) is not None
                for item in self.analyzed_files
            )
            or any(
                (rule := self.ignore_policy.matching_rule(item.path)) is None
                or rule.rule_id != item.rule_id
                for item in self.ignored_files
            )
        ):
            raise ValueError("discovery manifest is invalid")
        expected_languages: dict[LanguageId, list[DiscoveredLanguageFile]] = {}
        expected_dependencies: list[DependencyManifestEntry] = []
        for path in sorted(all_files):
            content_hash, rule_id = all_files[path]
            language = _language_for(path)
            if language is not None:
                expected_languages.setdefault(language, []).append(
                    DiscoveredLanguageFile(path, content_hash, rule_id)
                )
            dependency = _dependency_for(path)
            if dependency is not None:
                expected_dependencies.append(
                    DependencyManifestEntry(path, content_hash, *dependency, rule_id)
                )
        flattened_languages = {entry.language: list(entry.files) for entry in self.languages}
        if (
            flattened_languages != expected_languages
            or list(self.dependency_manifests) != expected_dependencies
            or self.manifest_sha256 != _discovery_manifest_hash(self)
        ):
            raise ValueError("discovery manifest is invalid")
