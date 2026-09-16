def fetch_invoice(tenant_id, invoice):
    """Policy: the requested tenant must equal the invoice tenant."""
    return invoice if invoice['tenant_id'] == tenant_id else None
