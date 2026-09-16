def disclose(record, allowed):
    """Policy: the confidential note is returned only after an allow decision."""
    return record['internal_note'] if allowed else None
