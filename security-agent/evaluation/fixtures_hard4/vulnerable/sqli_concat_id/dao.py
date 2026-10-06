import sqlite3


def by_id(uid):
    conn = sqlite3.connect("a.db")
    return conn.execute("SELECT * FROM users WHERE id = " + uid).fetchall()   # SINK
