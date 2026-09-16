def accepts_member(name):
    """Policy: archive extraction plan admits only relative, non-traversing names."""
    normalized = name.replace('\\', '/')
    return (
        not normalized.startswith('/')
        and ':' not in normalized
        and all(part not in {'', '..'} for part in normalized.split('/'))
    )
