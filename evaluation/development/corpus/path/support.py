from pathlib import Path


def file_for(root, name):
    """Educational helper: joins path data but does not enforce containment."""
    return Path(root) / name
