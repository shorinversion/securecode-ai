import sqlite3

def find_user(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")