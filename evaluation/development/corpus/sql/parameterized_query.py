def lookup(request, db):
    """Policy: HTTP input is supplied as a bound database parameter."""
    name = request.args.get('name')
    return db.execute('SELECT * FROM accounts WHERE name = ?', (name,))
