from support import where_clause


def report(request, db):
    """Violation: request input crosses a helper boundary into SQL execution."""
    name = request.args.get('name')
    return db.execute('SELECT * FROM events WHERE ' + where_clause(name))
