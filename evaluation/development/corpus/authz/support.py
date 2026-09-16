def load_invoice(invoice_id):
    """Educational backing store deliberately has no caller-tenant policy."""
    return {'invoice_id': invoice_id, 'tenant_id': 'unverified'}
