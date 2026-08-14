def get_user(request, db):
    user_id = request.args.get("user_id")
    query = make_runtime_query("users", user_id)
    return db.execute(query).fetchone()
