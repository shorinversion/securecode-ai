"""Protected administrative host admission for installed local Core scans."""

from __future__ import annotations

import os as os
from pathlib import Path

from . import local_product_host_git as _git_module
from . import local_product_host_host as _host_module
from . import local_product_host_linux as _linux_module
from . import local_product_host_windows as _windows_module
from .local_product_host_host import LocalProductHost
from .local_product_host_linux import _assert_linux_object_protected
from .local_product_host_primitives import (
    LocalProductHostError,
    _parse_record,
    _ProtectedAnchor,
)
from .local_product_host_primitives import (
    _canonical as _canonical,
)
from .local_product_host_windows import (
    _AclSizeInformation,
    _assert_windows_key_protected,
    _windows_sid_text,
)
from .local_provider_admission import LocalProviderEvidenceBundle

_read_platform_anchor = _host_module._read_platform_anchor


def load_local_product_host() -> LocalProductHost:
    """Load through facade-visible seams without weakening host validation."""
    original_reader = _host_module._read_platform_anchor
    original_parser = _host_module._parse_record
    try:
        _host_module._read_platform_anchor = _read_platform_anchor
        _host_module._parse_record = _parse_record
        return _host_module.load_local_product_host()
    finally:
        _host_module._read_platform_anchor = original_reader
        _host_module._parse_record = original_parser


def _read_linux_anchor() -> _ProtectedAnchor:
    original = _linux_module._assert_linux_object_protected
    try:
        _linux_module._assert_linux_object_protected = _assert_linux_object_protected
        return _linux_module._read_linux_anchor()
    finally:
        _linux_module._assert_linux_object_protected = original


def _assert_no_low_trust_write(
    advapi: object,
    dacl: int,
    *,
    file_object: bool = False,
    allow_ancestor_directory_creation: bool = False,
) -> None:
    original = _windows_module._windows_sid_text
    try:
        _windows_module._windows_sid_text = _windows_sid_text
        _windows_module._assert_no_low_trust_write(
            advapi,
            dacl,
            file_object=file_object,
            allow_ancestor_directory_creation=allow_ancestor_directory_creation,
        )
    finally:
        _windows_module._windows_sid_text = original


def verify_local_git_executable(expected_digest: str) -> Path:
    """Verify Git while preserving facade-visible protection seams."""
    original_linux = _git_module._assert_linux_object_protected
    original_windows = _git_module._assert_windows_key_protected
    try:
        _git_module._assert_linux_object_protected = _assert_linux_object_protected
        _git_module._assert_windows_key_protected = _assert_windows_key_protected
        return _git_module.verify_local_git_executable(expected_digest)
    finally:
        _git_module._assert_linux_object_protected = original_linux
        _git_module._assert_windows_key_protected = original_windows


for _host_type in (LocalProductHostError, _ProtectedAnchor, LocalProductHost, _AclSizeInformation):
    _host_type.__module__ = __name__
del _host_type

__all__ = [
    "LocalProductHost",
    "LocalProductHostError",
    "LocalProviderEvidenceBundle",
    "load_local_product_host",
    "verify_local_git_executable",
]
