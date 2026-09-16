def report(db):
    """Policy: a static query has no untrusted source."""
    return db.execute('SELECT count(*) FROM events')
