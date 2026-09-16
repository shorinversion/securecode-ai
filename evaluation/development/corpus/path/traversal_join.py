from pathlib import Path


def read(root, name):
    """Violation: an untrusted path segment reaches a filesystem path without containment."""
    return Path(root) / name
