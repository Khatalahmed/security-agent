import sqlite3


def lookup(nick):
    conn = sqlite3.connect("a.db")
    # Bound parameter: the stored value is data, never SQL text.
    return conn.execute(
        "SELECT body FROM msg WHERE author = ?", (nick,)).fetchall()
