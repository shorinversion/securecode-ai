from support import load_invoice


def fetch_invoice(invoice_id):
    """Violation: invoice_id reaches a disclosure sink without caller-tenant binding."""
    return load_invoice(invoice_id)
