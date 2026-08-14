def load_id(request):
    return request.args.get("user_id")
def build_query(value):
    return "SELECT * FROM users WHERE id = " + value
def get_user(request, db):
    return db.execute(build_query(load_id(request))).fetchone()
