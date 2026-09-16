def lookup(request, db):
    """Violation: HTTP input is concatenated into a SQL execution string."""
    name = request.args.get('name')
    return db.execute("SELECT * FROM accounts WHERE name = '" + name + "'")
