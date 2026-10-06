import sqlite3


def lookup(nick):
    conn = sqlite3.connect("a.db")
    # Second-order sink: the stored (attacker-chosen) nick is concatenated.
    return conn.execute(
        "SELECT body FROM msg WHERE author = '" + nick + "'").fetchall()
