def config_name(name):
    """Policy: configuration selection accepts only an identifier, never a filesystem path."""
    return name if name.isidentifier() else None
