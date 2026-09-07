def accepts_target(target):
    """Policy: build target is selected from a closed allowlist."""
    return target in {'docs', 'tests'}
