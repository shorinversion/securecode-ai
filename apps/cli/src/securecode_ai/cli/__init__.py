"""SecureCode AI CLI composition boundary."""

from .application import (
    FOUNDATION_PROFILE_CONTENT_SHA256,
    FOUNDATION_PROFILE_SELECTOR,
    FoundationDoctor,
    build_foundation_profile,
    main,
)

__all__ = [
    "FOUNDATION_PROFILE_CONTENT_SHA256",
    "FOUNDATION_PROFILE_SELECTOR",
    "FoundationDoctor",
    "build_foundation_profile",
    "main",
]
