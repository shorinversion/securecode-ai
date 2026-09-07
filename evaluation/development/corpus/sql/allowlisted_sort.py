def list_accounts(request, db):
    """Policy: a structural SQL identifier is selected from a closed allowlist."""
    requested = request.args.get('order')
    order = requested if requested in {'name', 'created_at'} else 'name'
    return db.execute('SELECT * FROM accounts ORDER BY ' + order)
