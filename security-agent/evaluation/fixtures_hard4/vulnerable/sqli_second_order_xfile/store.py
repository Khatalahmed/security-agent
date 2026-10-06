import sqlite3


def save(nick):
    conn = sqlite3.connect("a.db")
    conn.execute("INSERT INTO prefs(nick) VALUES(?)", (nick,))   # bound: safe write
    conn.commit()


def get_latest():
    conn = sqlite3.connect("a.db")
    return conn.execute(
        "SELECT nick FROM prefs ORDER BY rowid DESC LIMIT 1").fetchone()[0]
