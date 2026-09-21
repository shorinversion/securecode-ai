"""Real offline Git object reader integration and metadata attack checks."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

import pytest
from securecode_ai.adapters.git_snapshot import OfflineGitObjectReader, materialize_git_snapshot


class GitCommand(Protocol):
    def __call__(self, *args: str, content: bytes = b"") -> str: ...


NativeRepository = tuple[Path, GitCommand, OfflineGitObjectReader, str, str]


@pytest.fixture
def native_repository(tmp_path: Path) -> NativeRepository:
    executable = shutil.which("git")
    assert executable is not None, "Git is required for native intake verification"
    root = tmp_path / "repository.git"
    env = {
        name: os.environ[name]
        for name in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
        if name in os.environ
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_NAME="Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )

    def git(*args: str, content: bytes = b"") -> str:
        return (
            subprocess.check_output(
                [executable, f"--git-dir={root}", *args],
                input=content,
                env=env,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            .strip()
            .decode("ascii")
        )

    subprocess.check_call(
        [executable, "init", "--bare", "--quiet", str(root)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    blob = git("hash-object", "-w", "--stdin", content=b"original\r\n")
    tree = git("mktree", content=f"100644 blob {blob}\ta.py\n".encode())
    head = git("commit-tree", tree, content=b"fixture\n")
    git("update-ref", "refs/heads/main", head)
    reader = OfflineGitObjectReader(objects_dir=root / "objects", git_executable=Path(executable))
    return root, git, reader, head, blob


def test_native_packed_objects_ignore_original_config_and_checkout(
    native_repository: NativeRepository,
) -> None:
    root, git, reader, head, _ = native_repository
    git("repack", "-ad")
    (root / "config").write_text("invalid repository config\n", encoding="ascii")
    snapshot = materialize_git_snapshot(reader, head)
    assert snapshot.files[0].content == b"original\r\n"
    assert snapshot.files[0].path == "a.py"


def test_native_replacements_ignored_and_wrong_type_or_missing_fails(
    native_repository: NativeRepository,
) -> None:
    _, git, reader, head, blob = native_repository
    replacement = git("hash-object", "-w", "--stdin", content=b"poisoned")
    git("update-ref", f"refs/replace/{blob}", replacement)
    assert reader.read("blob", blob, max_bytes=100) == b"original\r\n"
    with pytest.raises(ValueError):
        reader.read("tree", head, max_bytes=10000)
    with pytest.raises(ValueError):
        reader.read("blob", "0" * 40, max_bytes=100)
    with pytest.raises(ValueError, match="budget"):
        reader.read("blob", blob, max_bytes=1)


def test_native_alternates_and_inherited_git_environment_rejected_or_ignored(
    native_repository: NativeRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, reader, head, _ = native_repository
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "invalid inherited config")
    monkeypatch.setenv("GIT_TRACE", str(root / "must-not-exist.log"))
    assert materialize_git_snapshot(reader, head).files[0].content == b"original\r\n"
    assert not (root / "must-not-exist.log").exists()
    (root / "objects" / "info" / "alternates").write_text("unadmitted-path\n", encoding="ascii")
    with pytest.raises(ValueError, match="alternates"):
        materialize_git_snapshot(reader, head)
