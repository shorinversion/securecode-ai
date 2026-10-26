import sqlite3


def find_user(name):
    connection = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return connection.execute(query).fetchall()
