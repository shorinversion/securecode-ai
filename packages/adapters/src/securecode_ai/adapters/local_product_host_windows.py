"""Windows protected-anchor and ACL access helpers."""

from __future__ import annotations

import ctypes
from typing import Protocol, cast

from .local_product_host_primitives import (
    _MAX_ANCHOR_VALUE_BYTES,
    _SHA256,
    _WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
    _WINDOWS_DACL_SECURITY_INFORMATION,
    _WINDOWS_ERROR_SUCCESS,
    _WINDOWS_HKLM,
    _WINDOWS_KEY_READ_64,
    _WINDOWS_OWNER_SECURITY_INFORMATION,
    _WINDOWS_REG_BINARY,
    _WINDOWS_SE_REGISTRY_KEY,
    _WINDOWS_SENSITIVE_ACCESS,
    _WINDOWS_TRUSTED_OWNERS,
    LocalProductHostError,
    _ProtectedAnchor,
    _reject,
)


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *arguments: object) -> int: ...


def _windows_function(library: object, name: str) -> _WindowsFunction:
    function: object = getattr(library, name, None)
    if not callable(function):
        _reject()
    return cast(_WindowsFunction, function)


def _windows_library(name: str) -> object:
    loader: object = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        _reject()
    library: object = loader(name, use_last_error=True)
    return library


def _read_windows_anchor() -> _ProtectedAnchor:
    advapi = _windows_library("advapi32")
    handles: list[int] = []
    try:
        root = _open_windows_key(advapi, _WINDOWS_HKLM, "")
        handles.append(root)
        _assert_windows_key_protected(root)
        software = _open_windows_key(advapi, root, "SOFTWARE")
        handles.append(software)
        _assert_windows_key_protected(software)
        anchor = _open_windows_key(advapi, software, "SecureCodeAI")
        handles.append(anchor)
        _assert_windows_key_protected(anchor)
        approval_digest = _read_windows_anchor_hash(advapi, anchor, "ApprovalRecordSha256")
        manifest_digest = _read_windows_anchor_hash(advapi, anchor, "ArtifactManifestSha256")
        approval = _read_windows_binary(advapi, anchor, "ApprovalRecord")
        manifest = _read_windows_binary(advapi, anchor, "ArtifactManifest")
        return _ProtectedAnchor(approval, approval_digest, manifest, manifest_digest)
    except LocalProductHostError:
        raise
    except Exception:
        _reject()
    finally:
        for handle in reversed(handles):
            _close_windows_key(advapi, handle)


def _open_windows_key(advapi: object, parent: int, name: str) -> int:
    opener = _windows_function(advapi, "RegOpenKeyExW")
    opener.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    opener.restype = ctypes.c_long
    handle = ctypes.c_void_p()
    if (
        opener(ctypes.c_void_p(parent), name, 8, _WINDOWS_KEY_READ_64, ctypes.byref(handle))
        != _WINDOWS_ERROR_SUCCESS
        or not handle.value
    ):
        _reject()
    # Opening a registry link itself must never silently follow its target.
    query = _windows_function(advapi, "RegQueryValueExW")
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    query.restype = ctypes.c_long
    kind, size = ctypes.c_uint32(), ctypes.c_uint32()
    link_status = query(
        handle, "SymbolicLinkValue", None, ctypes.byref(kind), None, ctypes.byref(size)
    )
    if link_status != 2:  # ERROR_FILE_NOT_FOUND is the only unambiguous absence.
        _close_windows_key(advapi, int(handle.value))
        _reject()
    return int(handle.value)


def _close_windows_key(advapi: object, handle: int) -> None:
    closer = _windows_function(advapi, "RegCloseKey")
    closer.argtypes = [ctypes.c_void_p]
    closer.restype = ctypes.c_long
    closer(ctypes.c_void_p(handle))


def _read_windows_anchor_hash(advapi: object, handle: int, name: str) -> str:
    raw = _read_windows_binary(advapi, handle, name)
    try:
        value = raw.decode("ascii")
    except UnicodeError:
        _reject()
    if _SHA256.fullmatch(value) is None:
        _reject()
    return value


def _read_windows_binary(advapi: object, handle: int, name: str) -> bytes:
    query = _windows_function(advapi, "RegQueryValueExW")
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    query.restype = ctypes.c_long
    kind = ctypes.c_uint32()
    size = ctypes.c_uint32()
    if (
        query(ctypes.c_void_p(handle), name, None, ctypes.byref(kind), None, ctypes.byref(size))
        != _WINDOWS_ERROR_SUCCESS
    ):
        _reject()
    if kind.value != _WINDOWS_REG_BINARY or not 0 < size.value <= _MAX_ANCHOR_VALUE_BYTES:
        _reject()
    buffer = (ctypes.c_ubyte * size.value)()
    actual = ctypes.c_uint32(size.value)
    if (
        query(ctypes.c_void_p(handle), name, None, ctypes.byref(kind), buffer, ctypes.byref(actual))
        != _WINDOWS_ERROR_SUCCESS
        or kind.value != _WINDOWS_REG_BINARY
        or actual.value != size.value
    ):
        _reject()
    return bytes(buffer)


def _assert_windows_key_protected(
    handle: int,
    *,
    object_type: int = _WINDOWS_SE_REGISTRY_KEY,
    allow_ancestor_directory_creation: bool = False,
) -> None:
    advapi = _windows_library("advapi32")
    descriptor = ctypes.c_void_p()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    getter = _windows_function(advapi, "GetSecurityInfo")
    getter.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    getter.restype = ctypes.c_uint32
    status = getter(
        ctypes.c_void_p(handle),
        object_type,
        _WINDOWS_OWNER_SECURITY_INFORMATION | _WINDOWS_DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if (
        status != _WINDOWS_ERROR_SUCCESS
        or not owner.value
        or not dacl.value
        or not descriptor.value
    ):
        _reject()
    try:
        if _windows_sid_text(advapi, owner.value) not in _WINDOWS_TRUSTED_OWNERS:
            _reject()
        _assert_no_low_trust_write(
            advapi,
            dacl.value,
            file_object=object_type == 1,
            allow_ancestor_directory_creation=allow_ancestor_directory_creation,
        )
    finally:
        local_free = _windows_function(_windows_library("kernel32"), "LocalFree")
        local_free(descriptor)


def _windows_sid_text(advapi: object, sid: int) -> str:
    converter = _windows_function(advapi, "ConvertSidToStringSidW")
    converter.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    converter.restype = ctypes.c_int
    output = ctypes.c_wchar_p()
    if not converter(ctypes.c_void_p(sid), ctypes.byref(output)) or output.value is None:
        _reject()
    try:
        return output.value
    finally:
        local_free = _windows_function(_windows_library("kernel32"), "LocalFree")
        local_free(output)


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [("ace_count", ctypes.c_uint32), ("_unused", ctypes.c_uint32 * 2)]


def _assert_no_low_trust_write(
    advapi: object,
    dacl: int,
    *,
    file_object: bool = False,
    allow_ancestor_directory_creation: bool = False,
) -> None:
    info = _AclSizeInformation()
    get_info = _windows_function(advapi, "GetAclInformation")
    get_info.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int]
    get_info.restype = ctypes.c_int
    if not get_info(ctypes.c_void_p(dacl), ctypes.byref(info), ctypes.sizeof(info), 2):
        _reject()
    get_ace = _windows_function(advapi, "GetAce")
    get_ace.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    get_ace.restype = ctypes.c_int
    for index in range(info.ace_count):
        ace = ctypes.c_void_p()
        if not get_ace(ctypes.c_void_p(dacl), index, ctypes.byref(ace)) or not ace.value:
            _reject()
        header = (ctypes.c_ubyte * 4).from_address(ace.value)
        if header[1] & 0x08:  # INHERIT_ONLY does not grant access on the opened object.
            continue
        if header[0] != _WINDOWS_ACCESS_ALLOWED_ACE_TYPE:
            _reject()
        mask = ctypes.c_uint32.from_address(ace.value + 4).value
        sensitive = _WINDOWS_SENSITIVE_ACCESS | (0x10 | 0x40 | 0x100 if file_object else 0)
        if file_object and allow_ancestor_directory_creation:
            # Creating an unrelated subdirectory cannot replace the retained
            # existing protected descendant. Add-file, delete-child, ACL/owner
            # changes and directory attributes remain forbidden. The executable
            # directory itself never receives this exception.
            sensitive &= ~0x4
        if (
            _windows_sid_text(advapi, ace.value + 8) not in _WINDOWS_TRUSTED_OWNERS
            and mask & sensitive
        ):
            _reject()
