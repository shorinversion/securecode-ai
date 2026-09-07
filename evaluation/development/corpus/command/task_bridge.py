from support import render


def build(task):
    """Violation: untrusted task crosses an inter-file boundary into shell syntax."""
    return render(task)
