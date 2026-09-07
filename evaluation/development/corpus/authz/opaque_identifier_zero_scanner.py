def disclose(record):
    """Violation: an opaque identifier does not authorize disclosure of internal_note."""
    return record['internal_note']
