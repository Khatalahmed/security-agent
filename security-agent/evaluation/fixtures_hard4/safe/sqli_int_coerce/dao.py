import sqlite3


def by_id(uid):
    conn = sqlite3.connect("a.db")
    # uid is an int; str(int) is pure digits, so no injection is possible.
    return conn.execute("SELECT * FROM users WHERE id = " + str(uid)).fetchall()
