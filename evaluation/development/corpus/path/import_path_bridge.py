from support import file_for


def read(root, name):
    """Violation: untrusted name is delegated to a join helper without containment."""
    return file_for(root, name)
