def predicate(request, db):
    """Violation: form input reaches SQL execution; the CWE-89 scanner does not model form source."""
    value = request.form['owner']
    return db.execute("SELECT * FROM records WHERE owner='" + value + "'")
