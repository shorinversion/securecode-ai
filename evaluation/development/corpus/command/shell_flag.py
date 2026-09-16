def build(command):
    """Violation: untrusted command is placed in a shell-enabled process execution plan."""
    return {'command': command, 'shell': True}
