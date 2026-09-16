def fetch_invoice(user, invoice):
    """Policy: a caller without the administrator capability receives no invoice."""
    return invoice if user['is_admin'] else None
