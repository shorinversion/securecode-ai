"""Linux protected-anchor access helpers."""

from __future__ import annotations

import json
import os
import stat

from .local_product_host_primitives import (
    _MAX_ANCHOR_VALUE_BYTES,
    _SHA256,
    LocalProductHostError,
    _closed_object,
    _ProtectedAnchor,
    _reject,
)


def _assert_linux_object_protected(fd: int, *, directory: bool) -> None:
    observed = os.fstat(fd)
    if (
        observed.st_uid != 0
        or observed.st_mode & 0o022
        or (directory and not stat.S_ISDIR(observed.st_mode))
        or (not directory and (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1))
    ):
        _reject()
    # Mode bits alone cannot establish effective protection with an ACL.
    list_xattrs = getattr(os, "listxattr", None)
    if not callable(list_xattrs) or any(
        name.startswith("system.posix_acl_") for name in list_xattrs(fd)
    ):
        _reject()


def _posix_constant(name: str) -> int:
    return int(getattr(os, name))


def _read_linux_anchor() -> _ProtectedAnchor:
    """Consume the fixed root-owned anchor through retained no-follow descriptors."""
    descriptors: list[int] = []
    try:
        flags = os.O_RDONLY | _posix_constant("O_CLOEXEC") | _posix_constant("O_NOFOLLOW")
        parent = os.open("/", flags | _posix_constant("O_DIRECTORY"))
        descriptors.append(parent)
        _assert_linux_object_protected(parent, directory=True)
        for name in ("etc", "securecode-ai"):
            parent = os.open(name, flags | _posix_constant("O_DIRECTORY"), dir_fd=parent)
            descriptors.append(parent)
            _assert_linux_object_protected(parent, directory=True)
        leaf = os.open("approval-anchor.json", flags | _posix_constant("O_NONBLOCK"), dir_fd=parent)
        descriptors.append(leaf)
        _assert_linux_object_protected(leaf, directory=False)
        raw = bytearray()
        while len(raw) <= _MAX_ANCHOR_VALUE_BYTES:
            chunk = os.read(leaf, min(65536, _MAX_ANCHOR_VALUE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not raw or len(raw) > _MAX_ANCHOR_VALUE_BYTES or b"\x00" in raw:
            _reject()
        document = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_closed_object)
        expected = {
            "approval_record",
            "approval_record_sha256",
            "artifact_manifest",
            "artifact_manifest_sha256",
        }
        if type(document) is not dict or set(document) != expected:
            _reject()
        if any(type(item) is not str for item in document.values()):
            _reject()
        for name in ("approval_record_sha256", "artifact_manifest_sha256"):
            if _SHA256.fullmatch(document[name]) is None:
                _reject()
        return _ProtectedAnchor(
            document["approval_record"].encode("utf-8"),
            document["approval_record_sha256"],
            document["artifact_manifest"].encode("utf-8"),
            document["artifact_manifest_sha256"],
        )
    except LocalProductHostError:
        raise
    except Exception:
        _reject()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
