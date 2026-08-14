def get_user(request, db):
    user_id = int(request.args.get("user_id"))
    return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
