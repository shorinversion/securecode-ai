"""Fixed synthetic public development snapshots for Core conformance plumbing.

The module creates deterministic in-memory Git closures but never executes their
source.  These fixtures are development recipes, not benchmark, LIVE, or
admission evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from securecode_ai.adapters.git_snapshot import GitObjectReader
from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.native_sources import (
    NativeSourceCatalogue,
    build_native_source_catalogue,
)
from securecode_ai.contracts import DataClass

_OID: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_TENANT: Final = "synthetic-public-development"
_REPOSITORY: Final = "synthetic-public-core-fixtures"
_CONTENT_KEY: Final = b"synthetic-public-core-fixture-content-key-v1" * 2
SourceFiles = tuple[tuple[str, bytes], ...]
ControlPair = tuple[SourceFiles, SourceFiles]


class PublicCoreFixtureError(ValueError):
    """Safe fixture-construction failure."""

    def __init__(self) -> None:
        super().__init__("public Core fixture is invalid")
        self.__cause__ = None
        self.__context__ = None


class FixtureProvenance(StrEnum):
    """This provenance never grants production or external-evaluation authority."""

    SYNTHETIC_DEVELOPMENT = "SYNTHETIC_DEVELOPMENT"


@dataclass(frozen=True, slots=True)
class SourceManifestHash:
    path: str
    content_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or not self.path
            or self.path.startswith("/")
            or "\\" in self.path
            or ".." in self.path.split("/")
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
        ):
            raise PublicCoreFixtureError()


@dataclass(frozen=True, slots=True)
class PublicCoreFixture:
    """Sealed first-party public development metadata and catalogue."""

    catalogue: NativeSourceCatalogue = field(repr=False)
    head_sha: str
    case: CoreCase
    language: str
    paths: tuple[str, ...]
    source_manifest_hashes: tuple[SourceManifestHash, ...]
    recipe_sha256: str
    provenance: FixtureProvenance = FixtureProvenance.SYNTHETIC_DEVELOPMENT

    def __post_init__(self) -> None:
        try:
            snapshot_paths = tuple(item.path for item in self.catalogue.snapshot.files)
            snapshot_hashes = tuple(
                SourceManifestHash(item.path, item.content_sha256)
                for item in self.catalogue.snapshot.files
            )
        except (AttributeError, TypeError, ValueError):
            raise PublicCoreFixtureError() from None
        if (
            type(self.catalogue) is not NativeSourceCatalogue
            or type(self.head_sha) is not str
            or _OID.fullmatch(self.head_sha) is None
            or self.head_sha != self.catalogue.snapshot.head_sha
            or type(self.case) is not CoreCase
            or type(self.language) is not str
            or self.language not in {"python", "javascript", "typescript", "go"}
            or type(self.paths) is not tuple
            or self.paths != tuple(sorted(self.paths))
            or self.paths != snapshot_paths
            or type(self.source_manifest_hashes) is not tuple
            or self.source_manifest_hashes != snapshot_hashes
            or type(self.recipe_sha256) is not str
            or _SHA256.fullmatch(self.recipe_sha256) is None
            or self.provenance is not FixtureProvenance.SYNTHETIC_DEVELOPMENT
            or not self.catalogue.indexes
            or not self.catalogue.anchors
        ):
            raise PublicCoreFixtureError()


class _FixtureReader(GitObjectReader):
    """Bounded in-memory object database for these fixed first-party recipes."""

    __slots__ = ("_objects",)

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], bytes] = {}

    def add(self, kind: str, content: bytes) -> str:
        if (
            type(kind) is not str
            or kind not in {"blob", "tree", "commit"}
            or type(content) is not bytes
        ):
            raise PublicCoreFixtureError()
        oid = hashlib.sha1(
            f"{kind} {len(content)}\0".encode("ascii") + content,
            usedforsecurity=False,
        ).hexdigest()
        self._objects[(kind, oid)] = bytes(content)
        return oid

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        if (
            type(kind) is not str
            or kind not in {"blob", "tree", "commit"}
            or type(oid) is not str
            or _OID.fullmatch(oid) is None
            or type(max_bytes) is not int
            or not 0 <= max_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("public fixture object request is invalid")
        content = self._objects.get((kind, oid))
        if content is None or len(content) > max_bytes:
            raise ValueError("public fixture object unavailable")
        return content


def _single(path: str, vulnerable: bytes, safe: bytes) -> ControlPair:
    return ((path, vulnerable),), ((path, safe),)


def _interfile(
    first_path: str,
    vulnerable: bytes,
    safe: bytes,
    second_path: str,
    vulnerable_second: bytes,
    safe_second: bytes,
) -> ControlPair:
    return (
        ((first_path, vulnerable), (second_path, vulnerable_second)),
        ((first_path, safe), (second_path, safe_second)),
    )


_PY_SINGLE = _single(
    "service.py",
    b'def find(db, value):\n    return db.execute("SELECT * FROM users WHERE id = " + value)\n',
    b'def find(db, value):\n    return db.execute("SELECT * FROM users WHERE id = ?", (value,))\n',
)
_PY_INTER = _interfile(
    "db.py",
    b"def run(db, query, values=()):\n    return db.execute(query, values) if values else db.execute(query)\n",
    b"def run(db, query, values=()):\n    return db.execute(query, values) if values else db.execute(query)\n",
    "service.py",
    b'from db import run\n\ndef handle(db, value):\n    query = "SELECT * FROM users WHERE id = " + value\n    return run(db, query)\n',
    b'from db import run\n\ndef handle(db, value):\n    query = "SELECT * FROM users WHERE id = ?"\n    return run(db, query, (value,))\n',
)
_JS_SINGLE = _single(
    "service.js",
    b'export function find(db, value) { return db.query("SELECT * FROM users WHERE id = " + value); }\n',
    b'export function find(db, value) { return db.query("SELECT * FROM users WHERE id = ?", [value]); }\n',
)
_JS_INTER = _interfile(
    "db.js",
    b"export function run(db, query, values = []) { return db.query(query, values); }\n",
    b"export function run(db, query, values = []) { return db.query(query, values); }\n",
    "service.js",
    b'import { run } from "./db.js";\nexport function handle(db, value) { const query = "SELECT * FROM users WHERE id = " + value; return run(db, query); }\n',
    b'import { run } from "./db.js";\nexport function handle(db, value) { const query = "SELECT * FROM users WHERE id = ?"; return run(db, query, [value]); }\n',
)
_TS_SINGLE = _single(
    "service.ts",
    b'export function find(db: any, value: string) { return db.query("SELECT * FROM users WHERE id = " + value); }\n',
    b'export function find(db: any, value: string) { return db.query("SELECT * FROM users WHERE id = ?", [value]); }\n',
)
_TS_INTER = _interfile(
    "db.ts",
    b"export function run(db: any, query: string, values: string[] = []) { return db.query(query, values); }\n",
    b"export function run(db: any, query: string, values: string[] = []) { return db.query(query, values); }\n",
    "service.ts",
    b'import { run } from "./db";\nexport function handle(db: any, value: string) { const query = "SELECT * FROM users WHERE id = " + value; return run(db, query); }\n',
    b'import { run } from "./db";\nexport function handle(db: any, value: string) { const query = "SELECT * FROM users WHERE id = ?"; return run(db, query, [value]); }\n',
)
_GO_SINGLE = _single(
    "service.go",
    b'package fixture\n\nimport "fmt"\n\ntype DB interface { Query(string, ...any) }\n\nfunc Find(db DB, value string) { db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", value)) }\n',
    b'package fixture\n\ntype DB interface { Query(string, ...any) }\n\nfunc Find(db DB, value string) { db.Query("SELECT * FROM users WHERE id = ?", value) }\n',
)
_GO_INTER = _interfile(
    "db.go",
    b"package fixture\n\ntype DB interface { Query(string, ...any) }\n\nfunc Run(db DB, query string, values ...any) { db.Query(query, values...) }\n",
    b"package fixture\n\ntype DB interface { Query(string, ...any) }\n\nfunc Run(db DB, query string, values ...any) { db.Query(query, values...) }\n",
    "service.go",
    b'package fixture\n\nimport "fmt"\n\nfunc Handle(db DB, value string) { query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", value); Run(db, query) }\n',
    b'package fixture\n\nfunc Handle(db DB, value string) { query := "SELECT * FROM users WHERE id = ?"; Run(db, query, value) }\n',
)


def _cases() -> dict[CoreCase, tuple[str, tuple[tuple[str, bytes], ...]]]:
    output: dict[CoreCase, tuple[str, tuple[tuple[str, bytes], ...]]] = {}
    for prefix, language, single, interfile in (
        ("PYTHON", "python", _PY_SINGLE, _PY_INTER),
        ("JAVASCRIPT", "javascript", _JS_SINGLE, _JS_INTER),
        ("TYPESCRIPT", "typescript", _TS_SINGLE, _TS_INTER),
        ("GO", "go", _GO_SINGLE, _GO_INTER),
    ):
        output[CoreCase[f"{prefix}_VULNERABLE"]] = (language, single[0])
        output[CoreCase[f"{prefix}_SAFE"]] = (language, single[1])
        output[CoreCase[f"{prefix}_INTERFILE"]] = (language, interfile[0])
        output[CoreCase[f"{prefix}_SAFE_INTERFILE"]] = (language, interfile[1])
    return output


_RECIPES: Final = _cases()


def _recipe_sha256(case: CoreCase, language: str, sources: tuple[tuple[str, bytes], ...]) -> str:
    material = {
        "case": case.value,
        "language": language,
        "paths": [path for path, _ in sources],
        "source_manifest_hashes": [hashlib.sha256(content).hexdigest() for _, content in sources],
        "provenance": FixtureProvenance.SYNTHETIC_DEVELOPMENT.value,
    }
    return hashlib.sha256(
        json.dumps(material, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    ).hexdigest()


def build_public_core_fixture(case: CoreCase) -> PublicCoreFixture:
    """Build one sealed synthetic public development snapshot through production intake."""

    if type(case) is not CoreCase:
        raise PublicCoreFixtureError()
    recipe = _RECIPES.get(case)
    if recipe is None:
        raise PublicCoreFixtureError()
    language, sources = recipe
    try:
        reader = _FixtureReader()
        entries = []
        for path, content in sources:
            blob = reader.add("blob", content)
            entries.append(b"100644 " + path.encode("ascii") + b"\0" + bytes.fromhex(blob))
        tree = reader.add("tree", b"".join(entries))
        head = reader.add(
            "commit",
            f"tree {tree}\n\nsynthetic public Core development fixture\n".encode("ascii"),
        )
        catalogue = build_native_source_catalogue(
            reader=reader,
            head_sha=head,
            tenant_id=_TENANT,
            repository_id=_REPOSITORY,
            content_key=_CONTENT_KEY,
            data_class=DataClass.PUBLIC,
        )
        manifest = tuple(
            SourceManifestHash(path, hashlib.sha256(content).hexdigest())
            for path, content in sources
        )
        return PublicCoreFixture(
            catalogue=catalogue,
            head_sha=head,
            case=case,
            language=language,
            paths=tuple(path for path, _ in sources),
            source_manifest_hashes=manifest,
            recipe_sha256=_recipe_sha256(case, language, sources),
        )
    except (AttributeError, TypeError, UnicodeError, ValueError):
        raise PublicCoreFixtureError() from None


__all__ = [
    "FixtureProvenance",
    "PublicCoreFixture",
    "PublicCoreFixtureError",
    "SourceManifestHash",
    "build_public_core_fixture",
]
