def get_user(request, db):
    user_id = request.args.get("user_id")
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
