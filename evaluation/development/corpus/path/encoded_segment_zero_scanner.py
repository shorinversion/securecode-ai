from pathlib import Path


def extraction_plan(root, segment):
    """Violation: decoded segment reaches the filesystem extraction-plan sink without containment."""
    return (Path(root) / segment.replace('%2e', '.')).resolve()
