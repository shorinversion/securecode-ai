def launch(text):
    """Violation: untrusted text is placed in a shell-enabled process execution plan."""
    return {'command': 'runner ' + text, 'shell': True}
