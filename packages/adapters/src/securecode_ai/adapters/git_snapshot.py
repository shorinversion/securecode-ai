"""Verify immutable Git commit/tree/blob closure without opening a checkout."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from securecode_ai.core.tool_policy import TOOL_ARGUMENT_SCHEMA_VERSION, ReadRangeArguments

_OID = re.compile(r"[0-9a-f]{40}\Z")
_CREATE_NO_WINDOW: Final[int] = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class GitObjectReader(Protocol):
    """Host-admitted offline reader; no checkout/filter/provider authority."""

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes: ...


class OfflineGitObjectReader:
    """Read a protected host-owned object DB through a disposable config-free repo.

    The executable and object database metadata are host trust inputs. Untrusted
    fixtures must never write this directory or receive this reader. No original
    repository config, refs, replacements, hooks or checkout paths are consumed.
    """

    def __init__(self, *, objects_dir: Path, git_executable: Path, timeout_seconds: int = 10):
        if (
            not isinstance(objects_dir, Path)
            or not isinstance(git_executable, Path)
            or not objects_dir.is_absolute()
            or str(objects_dir).startswith(("\\\\", "//"))
            or not git_executable.is_absolute()
            or not objects_dir.is_dir()
            or objects_dir.is_symlink()
            or not git_executable.is_file()
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 30
        ):
            raise ValueError("offline Git reader configuration is invalid")
        self._objects = objects_dir
        self._git = git_executable
        self._timeout = timeout_seconds

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        if (
            kind not in ("commit", "tree", "blob")
            or type(oid) is not str
            or _OID.fullmatch(oid) is None
            or type(max_bytes) is not int
            or not 0 <= max_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("offline Git object request is invalid")
        info = self._objects / "info"
        alternates = info / "alternates"
        if info.is_symlink() or alternates.exists() or alternates.is_symlink():
            raise ValueError("offline Git alternates are unsupported")
        env = {
            name: os.environ[name]
            for name in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
            if name in os.environ
        }
        env.update(
            GIT_OBJECT_DIRECTORY=str(self._objects),
            GIT_ALTERNATE_OBJECT_DIRECTORIES="",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_SYSTEM=os.devnull,
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_COUNT="0",
            GIT_TERMINAL_PROMPT="0",
            GIT_NO_LAZY_FETCH="1",
            GIT_NO_REPLACE_OBJECTS="1",
            GIT_ALLOW_PROTOCOL="",
            GIT_PROTOCOL_FROM_USER="0",
            GIT_OPTIONAL_LOCKS="0",
            LC_ALL="C",
        )
        try:
            with tempfile.TemporaryDirectory(prefix="securecode-git-reader-") as directory:
                root = Path(directory)
                (root / "objects").mkdir()
                (root / "refs").mkdir()
                (root / "HEAD").write_text("ref: refs/heads/unused\n", encoding="ascii")
                (root / "config").write_text(
                    "[core]\nrepositoryformatversion = 0\nbare = true\n", encoding="ascii"
                )
                argv = [
                    str(self._git),
                    "--no-pager",
                    "--no-replace-objects",
                    "--no-lazy-fetch",
                    "--no-optional-locks",
                    "-c",
                    "protocol.allow=never",
                    "-c",
                    "protocol.file.allow=never",
                    f"--git-dir={root}",
                    "cat-file",
                    kind,
                    oid,
                ]
                with subprocess.Popen(
                    argv,
                    env=env,
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
                ) as process:

                    def terminate() -> None:
                        with suppress(OSError):
                            process.kill()

                    watchdog = threading.Timer(self._timeout, terminate)
                    watchdog.daemon = True
                    watchdog.start()
                    try:
                        assert process.stdout is not None
                        content = process.stdout.read(max_bytes + 1)
                        if not isinstance(content, bytes):
                            raise ValueError("offline Git output is invalid")
                        if len(content) > max_bytes:
                            terminate()
                            raise ValueError("offline Git object exceeds budget")
                        if process.wait(timeout=self._timeout) != 0:
                            raise ValueError("offline Git object read failed")
                        envelope = f"{kind} {len(content)}\0".encode("ascii") + content
                        if hashlib.sha1(envelope, usedforsecurity=False).hexdigest() != oid:
                            raise ValueError("offline Git object type or identity mismatch")
                        return content
                    finally:
                        watchdog.cancel()
                        if process.poll() is None:
                            terminate()
                            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("offline Git object read failed") from None


@dataclass(frozen=True, slots=True)
class GitSnapshotFile:
    path: str
    blob_oid: str
    content_sha256: str
    content: bytes


@dataclass(frozen=True, slots=True)
class GitRevisionSnapshot:
    head_sha: str
    tree_oid: str
    files: tuple[GitSnapshotFile, ...]


def materialize_git_snapshot(
    reader: GitObjectReader,
    head_sha: str,
    *,
    max_files: int = 4096,
    max_file_bytes: int = 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
    max_depth: int = 32,
) -> GitRevisionSnapshot:
    """Recompute every object identity and reject incomplete or unsupported trees.

    Returned bytes are commit contents, including binary files. Parsing and ignore
    policy happen later, and cannot silently change this snapshot's source identity.
    """
    if type(head_sha) is not str or _OID.fullmatch(head_sha) is None:
        raise ValueError("Git revision is invalid")
    limits = (max_files, max_file_bytes, max_total_bytes, max_depth)
    ceilings = (4096, 16 * 1024 * 1024, 64 * 1024 * 1024, 64)
    if any(
        type(value) is not int or not 0 < value <= cap
        for value, cap in zip(limits, ceilings, strict=True)
    ):
        raise ValueError("Git snapshot limits are invalid")
    object_bytes = 0
    object_count = 0

    def verified(kind: str, oid: str, cap: int) -> bytes:
        nonlocal object_bytes, object_count
        if _OID.fullmatch(oid) is None:
            raise ValueError("Git object identity is invalid")
        object_count += 1
        if object_count > 16_384:
            raise ValueError("Git object count exceeds budget")
        content = reader.read(kind, oid, max_bytes=cap)
        if type(content) is not bytes or len(content) > cap:
            raise ValueError("Git object exceeds budget")
        object_bytes += len(content)
        if object_bytes > max_total_bytes + 8 * 1024 * 1024:
            raise ValueError("Git object closure exceeds budget")
        envelope = f"{kind} {len(content)}\0".encode("ascii") + content
        if hashlib.sha1(envelope, usedforsecurity=False).hexdigest() != oid:
            raise ValueError("Git object hash mismatch")
        return content

    commit = verified("commit", head_sha, 1024 * 1024)
    header, separator, _ = commit.partition(b"\n\n")
    lines = header.split(b"\n")
    if not separator or not lines or not re.fullmatch(b"tree [0-9a-f]{40}", lines[0]):
        raise ValueError("Git commit header is invalid")
    if sum(line.startswith(b"tree ") for line in lines) != 1:
        raise ValueError("Git commit tree is ambiguous")
    tree_oid = lines[0][5:].decode("ascii")
    files: list[GitSnapshotFile] = []
    total = 0

    def walk(oid: str, prefix: str, depth: int) -> None:
        nonlocal total
        if depth > max_depth:
            raise ValueError("Git tree exceeds depth budget")
        tree = verified("tree", oid, 4 * 1024 * 1024)
        cursor = 0
        names: set[str] = set()
        while cursor < len(tree):
            terminator = tree.find(b"\0", cursor)
            if terminator < 0 or terminator + 21 > len(tree):
                raise ValueError("Git tree entry is invalid")
            entry = tree[cursor:terminator]
            mode, space, raw_name = entry.partition(b" ")
            if not space or not raw_name or b"/" in raw_name:
                raise ValueError("Git tree path is invalid")
            try:
                name = raw_name.decode("utf-8", errors="strict")
            except UnicodeError:
                raise ValueError("Git tree path encoding is invalid") from None
            path = prefix + name
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, head_sha, path, 1, 1)
            if name in names:
                raise ValueError("Git tree path is ambiguous")
            names.add(name)
            child_oid = tree[terminator + 1 : terminator + 21].hex()
            cursor = terminator + 21
            if mode == b"40000":
                walk(child_oid, path + "/", depth + 1)
            elif mode in (b"100644", b"100755"):
                if len(files) >= max_files:
                    raise ValueError("Git snapshot exceeds file budget")
                content = verified("blob", child_oid, min(max_file_bytes, max_total_bytes - total))
                total += len(content)
                files.append(
                    GitSnapshotFile(path, child_oid, hashlib.sha256(content).hexdigest(), content)
                )
            else:
                raise ValueError("Git snapshot contains unsupported entry")

    walk(tree_oid, "", 0)
    return GitRevisionSnapshot(head_sha, tree_oid, tuple(sorted(files, key=lambda item: item.path)))
