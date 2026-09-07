from pathlib import Path


def read(root, name):
    """Policy: resolved child paths must remain below the resolved root."""
    candidate = (Path(root) / name).resolve()
    return candidate if candidate.is_relative_to(Path(root).resolve()) else None
