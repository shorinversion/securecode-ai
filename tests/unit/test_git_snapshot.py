"""Independent negative oracles for immutable Git object admission."""

import hashlib

import pytest
from securecode_ai.adapters.git_snapshot import materialize_git_snapshot


class Objects:
    def __init__(self) -> None:
        self.contents: dict[tuple[str, str], bytes] = {}

    def add(self, kind: str, content: bytes) -> str:
        oid = hashlib.sha1(
            f"{kind} {len(content)}\0".encode() + content, usedforsecurity=False
        ).hexdigest()
        self.contents[(kind, oid)] = content
        return oid

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        return self.contents[(kind, oid)]


def _repository(entries: bytes | None = None) -> tuple[Objects, str, str]:
    reader = Objects()
    blob = reader.add("blob", b"original\r\n")
    tree = reader.add(
        "tree", entries if entries is not None else b"100644 a.py\0" + bytes.fromhex(blob)
    )
    head = reader.add(
        "commit",
        f"tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nmessage\n".encode(),
    )
    return reader, head, blob


def test_snapshot_reads_exact_objects_and_retains_original_bytes() -> None:
    reader, head, blob = _repository()
    snapshot = materialize_git_snapshot(reader, head)
    reader.contents[("blob", blob)] = b"changed"
    assert snapshot.files[0].content == b"original\r\n"
    assert snapshot.files[0].blob_oid == blob
    assert snapshot.files[0].content_sha256 == hashlib.sha256(b"original\r\n").hexdigest()


@pytest.mark.parametrize("kind", ["commit", "tree", "blob"])
def test_tampered_object_body_never_admitted(kind: str) -> None:
    reader, head, _ = _repository()
    key = next(key for key in reader.contents if key[0] == kind)
    reader.contents[key] += b"poison"
    with pytest.raises(ValueError, match="hash mismatch"):
        materialize_git_snapshot(reader, head)


@pytest.mark.parametrize("mode", [b"120000", b"160000", b"999999"])
def test_links_submodules_and_unknown_modes_rejected(mode: bytes) -> None:
    reader, head, _ = _repository(mode + b" a.py\0" + bytes(20))
    with pytest.raises(ValueError, match="unsupported entry"):
        materialize_git_snapshot(reader, head)


def test_duplicate_and_traversal_paths_rejected() -> None:
    reader = Objects()
    blob = reader.add("blob", b"content")
    for name, count in [(b"a.py", 2), (b"../outside", 1)]:
        tree = reader.add("tree", (b"100644 " + name + b"\0" + bytes.fromhex(blob)) * count)
        head = reader.add("commit", f"tree {tree}\n\nmessage".encode())
        with pytest.raises(ValueError):
            materialize_git_snapshot(reader, head)


def test_limits_remain_hard_and_invalid_parameters_rejected() -> None:
    reader, head, _ = _repository()
    with pytest.raises(ValueError, match="budget"):
        materialize_git_snapshot(reader, head, max_file_bytes=1)
    for limits in ({"max_files": True}, {"max_depth": 0}, {"max_total_bytes": 2**40}):
        with pytest.raises(ValueError, match="limits"):
            materialize_git_snapshot(reader, head, **limits)


def test_nested_binary_snapshot_and_file_budget() -> None:
    reader = Objects()
    blob = reader.add("blob", bytes(range(256)))
    subtree = reader.add("tree", b"100755 a.bin\0" + bytes.fromhex(blob))
    tree = reader.add(
        "tree", b"40000 sub\0" + bytes.fromhex(subtree) + b"100644 b.bin\0" + bytes.fromhex(blob)
    )
    head = reader.add("commit", f"tree {tree}\n\nmessage".encode())
    snapshot = materialize_git_snapshot(reader, head)
    assert [item.path for item in snapshot.files] == ["b.bin", "sub/a.bin"]
    assert snapshot.files[0].content == bytes(range(256))
    with pytest.raises(ValueError, match="file budget"):
        materialize_git_snapshot(reader, head, max_files=1)
