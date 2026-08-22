"""P2.2 deterministic ignore, language, dependency and change discovery tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
import securecode_ai.core.discovery as discovery_module
from securecode_ai.core import (
    ChangedFileStatus,
    DependencyEcosystem,
    DependencyManifestKind,
    DiscoveryError,
    DiscoveryErrorCode,
    IgnorePolicy,
    IgnoreRule,
    IgnoreRuleKind,
    LanguageId,
    LanguageSupport,
    RepositoryFile,
    RepositoryInventory,
    build_changed_files_map,
    discover_repository,
    repository_tree_sha256,
)


def _file(path: str, content: bytes) -> RepositoryFile:
    return RepositoryFile(path, len(content), hashlib.sha256(content).hexdigest())


def _inventory(*files: RepositoryFile) -> RepositoryInventory:
    ordered = tuple(sorted(files, key=lambda item: item.path))
    return RepositoryInventory(
        files=ordered,
        total_bytes=sum(item.size_bytes for item in ordered),
        tree_sha256=repository_tree_sha256(ordered),
    )


def _policy(*rules: IgnoreRule, version: str = "1.0.0") -> IgnorePolicy:
    return IgnorePolicy("core-analysis", version, tuple(rules))


def test_mixed_language_and_dependency_discovery_is_explicit_and_stable() -> None:
    inventory = _inventory(
        _file("app/main.py", b"python"),
        _file("app/STUB.PYI", b"python-stub"),
        _file("frontend/app.js", b"javascript"),
        _file("frontend/types.tsx", b"typescript"),
        _file("go/cmd/main.go", b"go"),
        _file("pyproject.toml", b"project"),
        _file("requirements-dev.txt", b"test dependency"),
        _file("frontend/package-lock.json", b"lock"),
        _file("go/go.mod", b"module"),
        _file("README.md", b"readme"),
    )

    first = discover_repository(inventory, _policy())
    second = discover_repository(inventory, _policy())

    assert first == second
    assert first.manifest_sha256 == second.manifest_sha256
    assert [(entry.language, entry.support) for entry in first.languages] == [
        (LanguageId.GO, LanguageSupport.UNSUPPORTED),
        (LanguageId.JAVASCRIPT, LanguageSupport.UNSUPPORTED),
        (LanguageId.PYTHON, LanguageSupport.SUPPORTED),
        (LanguageId.TYPESCRIPT, LanguageSupport.UNSUPPORTED),
    ]
    assert [(entry.ecosystem, entry.kind, entry.path) for entry in first.dependency_manifests] == [
        (
            DependencyEcosystem.JAVASCRIPT,
            DependencyManifestKind.PACKAGE_LOCK,
            "frontend/package-lock.json",
        ),
        (DependencyEcosystem.GO, DependencyManifestKind.GO_MOD, "go/go.mod"),
        (DependencyEcosystem.PYTHON, DependencyManifestKind.PYPROJECT, "pyproject.toml"),
        (
            DependencyEcosystem.PYTHON,
            DependencyManifestKind.REQUIREMENTS,
            "requirements-dev.txt",
        ),
    ]


def test_policy_owned_ignore_is_explicit_for_source_and_dependency_manifests() -> None:
    policy = _policy(
        IgnoreRule("generated", IgnoreRuleKind.SUBTREE, "generated"),
        IgnoreRule("maps", IgnoreRuleKind.SUFFIX, ".map"),
        IgnoreRule("lock", IgnoreRuleKind.PATH, "vendor/package-lock.json"),
    )
    inventory = _inventory(
        _file("generated/hidden.go", b"go"),
        _file("public/app.js.map", b"map"),
        _file("src/main.py", b"python"),
        _file("vendor/package-lock.json", b"lock"),
    )

    manifest = discover_repository(inventory, policy)

    assert [item.path for item in manifest.analyzed_files] == ["src/main.py"]
    assert [(item.path, item.rule_id) for item in manifest.ignored_files] == [
        ("generated/hidden.go", "generated"),
        ("public/app.js.map", "maps"),
        ("vendor/package-lock.json", "lock"),
    ]
    go = next(entry for entry in manifest.languages if entry.language is LanguageId.GO)
    assert go.support is LanguageSupport.UNSUPPORTED
    assert go.files[0].ignored_by_rule_id == "generated"
    dependency = manifest.dependency_manifests[0]
    assert dependency.path == "vendor/package-lock.json"
    assert dependency.ignored_by_rule_id == "lock"


def test_repository_gitignore_is_inventory_data_not_executable_policy() -> None:
    inventory = _inventory(
        _file(".gitignore", b"src/**\n"),
        _file("src/main.py", b"python"),
    )

    manifest = discover_repository(inventory, _policy())

    assert [item.path for item in manifest.analyzed_files] == [".gitignore", "src/main.py"]
    assert manifest.ignored_files == ()


@pytest.mark.parametrize(
    "rule",
    [
        ("UPPER", IgnoreRuleKind.PATH, "safe"),
        ("bad", IgnoreRuleKind.PATH, "../escape"),
        ("bad", IgnoreRuleKind.SUBTREE, "/absolute"),
        ("bad", IgnoreRuleKind.SUFFIX, "py"),
        ("bad", IgnoreRuleKind.SUFFIX, "."),
    ],
)
def test_invalid_ignore_rules_are_rejected(
    rule: tuple[str, IgnoreRuleKind, str],
) -> None:
    with pytest.raises(ValueError, match="ignore rule is invalid"):
        IgnoreRule(*rule)


def test_duplicate_and_over_budget_ignore_policy_is_rejected() -> None:
    rule = IgnoreRule("one", IgnoreRuleKind.PATH, "build")
    with pytest.raises(ValueError, match="ignore policy is invalid"):
        _policy(rule, rule)
    rules = tuple(
        IgnoreRule(f"r{index}", IgnoreRuleKind.PATH, f"path-{index}") for index in range(257)
    )
    with pytest.raises(ValueError, match="ignore policy is invalid"):
        _policy(*rules)


@pytest.mark.parametrize(
    "first,second",
    [
        (
            IgnoreRule("lower", IgnoreRuleKind.PATH, "build"),
            IgnoreRule("upper", IgnoreRuleKind.PATH, "BUILD"),
        ),
        (
            IgnoreRule("path", IgnoreRuleKind.PATH, "Straße"),
            IgnoreRule("tree", IgnoreRuleKind.SUBTREE, "STRASSE"),
        ),
        (
            IgnoreRule("lower", IgnoreRuleKind.SUFFIX, ".py"),
            IgnoreRule("upper", IgnoreRuleKind.SUFFIX, ".PY"),
        ),
    ],
)
def test_casefold_colliding_ignore_rules_are_rejected(
    first: IgnoreRule,
    second: IgnoreRule,
) -> None:
    with pytest.raises(ValueError, match="ignore policy is invalid"):
        _policy(first, second)


def test_ignore_rule_path_budgets_accept_boundaries_and_reject_overflow() -> None:
    component = "a" * 255
    byte_boundary = "/".join([component] * 15 + ["b" * 127, "c" * 128])
    depth_boundary = "/".join(["a"] * 256)
    assert len(byte_boundary.encode()) == 4096
    assert len(depth_boundary.split("/")) == 256
    assert IgnoreRule("bytes-ok", IgnoreRuleKind.PATH, byte_boundary).value == byte_boundary
    assert IgnoreRule("depth-ok", IgnoreRuleKind.SUBTREE, depth_boundary).value == depth_boundary

    with pytest.raises(ValueError, match="ignore rule is invalid"):
        IgnoreRule("component", IgnoreRuleKind.PATH, "a" * 256)
    with pytest.raises(ValueError, match="ignore rule is invalid"):
        IgnoreRule("bytes", IgnoreRuleKind.PATH, f"{byte_boundary}a")
    with pytest.raises(ValueError, match="ignore rule is invalid"):
        IgnoreRule("depth", IgnoreRuleKind.SUBTREE, "/".join(["a"] * 257))


def test_changed_files_map_classifies_exact_path_and_hash_without_rename_guess() -> None:
    policy = _policy(IgnoreRule("ignored", IgnoreRuleKind.SUBTREE, "ignored"))
    base = discover_repository(
        _inventory(
            _file("deleted.py", b"old"),
            _file("modified.py", b"old"),
            _file("same.py", b"same"),
            _file("ignored/base.py", b"not compared"),
        ),
        policy,
    )
    head = discover_repository(
        _inventory(
            _file("added.py", b"new"),
            _file("modified.py", b"new"),
            _file("same.py", b"same"),
            _file("ignored/head.py", b"not compared"),
        ),
        policy,
    )

    changed = build_changed_files_map(base, head)

    assert [(entry.path, entry.status) for entry in changed.entries] == [
        ("added.py", ChangedFileStatus.ADDED),
        ("deleted.py", ChangedFileStatus.DELETED),
        ("ignored/base.py", ChangedFileStatus.DELETED),
        ("ignored/head.py", ChangedFileStatus.ADDED),
        ("modified.py", ChangedFileStatus.MODIFIED),
        ("same.py", ChangedFileStatus.UNCHANGED),
    ]
    ignored = [entry for entry in changed.entries if entry.path.startswith("ignored/")]
    assert ignored[0].base_ignored_by_rule_id == "ignored"
    assert ignored[0].head_ignored_by_rule_id is None
    assert ignored[1].base_ignored_by_rule_id is None
    assert ignored[1].head_ignored_by_rule_id == "ignored"
    assert changed == build_changed_files_map(base, head)
    assert len(changed.map_sha256) == 64


def test_changed_files_map_rejects_policy_mismatch() -> None:
    inventory = _inventory(_file("main.py", b"python"))
    base = discover_repository(inventory, _policy(version="1.0.0"))
    head = discover_repository(inventory, _policy(version="1.0.1"))

    with pytest.raises(DiscoveryError) as raised:
        build_changed_files_map(base, head)
    assert raised.value.code is DiscoveryErrorCode.POLICY_MISMATCH
    assert str(raised.value) == "repository discovery failed"


def test_manifest_and_map_hashes_reject_tampering() -> None:
    manifest = discover_repository(_inventory(_file("main.py", b"python")), _policy())
    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(manifest, manifest_sha256="0" * 64)

    changed = build_changed_files_map(manifest, manifest)
    with pytest.raises(ValueError, match="changed files map is invalid"):
        replace(changed, map_sha256="0" * 64)


def test_manifest_rejects_recomputed_inventory_and_policy_authority_forgery() -> None:
    manifest = discover_repository(_inventory(_file("main.py", b"python")), _policy())
    forged_inventory_hash = "0" * 64
    forged_manifest_hash = discovery_module._canonical_hash(
        discovery_module._discovery_payload(
            forged_inventory_hash,
            manifest.ignore_policy,
            manifest.analyzed_files,
            manifest.ignored_files,
            manifest.languages,
            manifest.dependency_manifests,
        )
    )
    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(
            manifest,
            inventory_tree_sha256=forged_inventory_hash,
            manifest_sha256=forged_manifest_hash,
        )

    forged_policy = _policy(
        IgnoreRule("hide-source", IgnoreRuleKind.PATH, "main.py"),
        version="9.9.9",
    )
    forged_policy_manifest_hash = discovery_module._canonical_hash(
        discovery_module._discovery_payload(
            manifest.inventory_tree_sha256,
            forged_policy,
            manifest.analyzed_files,
            manifest.ignored_files,
            manifest.languages,
            manifest.dependency_manifests,
        )
    )
    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(
            manifest,
            ignore_policy=forged_policy,
            manifest_sha256=forged_policy_manifest_hash,
        )


def test_manifest_rejects_recomputed_duplicate_analyzed_path_forgery() -> None:
    manifest = discover_repository(_inventory(_file("main.py", b"python")), _policy())
    duplicated_files = manifest.analyzed_files * 2
    forged_inventory_hash = repository_tree_sha256(duplicated_files)
    forged_manifest_hash = discovery_module._canonical_hash(
        discovery_module._discovery_payload(
            forged_inventory_hash,
            manifest.ignore_policy,
            duplicated_files,
            manifest.ignored_files,
            manifest.languages,
            manifest.dependency_manifests,
        )
    )

    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(
            manifest,
            inventory_tree_sha256=forged_inventory_hash,
            analyzed_files=duplicated_files,
            manifest_sha256=forged_manifest_hash,
        )


def test_changed_map_rederives_entries_from_bound_manifest_objects() -> None:
    policy = _policy()
    base = discover_repository(_inventory(_file("main.py", b"old")), policy)
    head = discover_repository(_inventory(_file("main.py", b"new")), policy)
    changed = build_changed_files_map(base, head)
    forged_base = discover_repository(
        _inventory(_file("extra.py", b"extra"), _file("main.py", b"old")),
        policy,
    )
    forged_map_hash = discovery_module._changed_map_hash_values(
        forged_base.manifest_sha256,
        head.manifest_sha256,
        policy.content_sha256,
        changed.entries,
    )

    with pytest.raises(ValueError, match="changed files map is invalid"):
        replace(
            changed,
            base_manifest=forged_base,
            map_sha256=forged_map_hash,
        )


def test_manifest_rejects_over_budget_derived_tuple_before_projection() -> None:
    manifest = discover_repository(_inventory(_file("main.py", b"python")), _policy())
    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(
            manifest,
            languages=manifest.languages * 5,
        )
    with pytest.raises(ValueError, match="discovery manifest is invalid"):
        replace(
            manifest,
            dependency_manifests=(
                discovery_module.DependencyManifestEntry(
                    "package.json",
                    "0" * 64,
                    discovery_module.DependencyEcosystem.JAVASCRIPT,
                    discovery_module.DependencyManifestKind.PACKAGE_JSON,
                    None,
                ),
                discovery_module.DependencyManifestEntry(
                    "package-lock.json",
                    "1" * 64,
                    discovery_module.DependencyEcosystem.JAVASCRIPT,
                    discovery_module.DependencyManifestKind.PACKAGE_LOCK,
                    None,
                ),
            ),
        )


def test_language_entry_accepts_exact_file_limit_and_rejects_overflow() -> None:
    maximum = discovery_module._MAX_DISCOVERY_FILES
    files = tuple(
        discovery_module.DiscoveredLanguageFile(
            f"src/f{index:06d}.py",
            "0" * 64,
            None,
        )
        for index in range(maximum)
    )
    boundary = discovery_module.LanguageManifestEntry(
        LanguageId.PYTHON,
        LanguageSupport.SUPPORTED,
        files,
    )
    assert len(boundary.files) == maximum

    with pytest.raises(ValueError, match="language manifest entry is invalid"):
        discovery_module.LanguageManifestEntry(
            LanguageId.PYTHON,
            LanguageSupport.SUPPORTED,
            (*files, files[-1]),
        )


def test_discovery_rejects_forged_types_without_echoing_input() -> None:
    inventory = _inventory(_file("main.py", b"python"))
    with pytest.raises(TypeError, match="repository inventory is invalid"):
        discover_repository(object(), _policy())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ignore policy is invalid"):
        discover_repository(inventory, object())  # type: ignore[arg-type]
