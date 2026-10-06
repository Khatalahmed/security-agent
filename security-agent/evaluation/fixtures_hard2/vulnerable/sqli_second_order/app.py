"""HARD/VULN - second-order SQL injection.

Ground truth: sqli. `set_nickname` stores the user's nickname with a BOUND
parameter - that write is textbook-safe and looks it. The bug is in `greet`,
which reads the stored nickname back and concatenates it straight into a query.
The tainting input and the dangerous sink live in different request handlers,
so single-pass "where does request.args go?" taint will not connect them; the
value re-enters as trusted-looking data from the database. That is the essence
of a second-order injection.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def _db():
    return sqlite3.connect("app.db")


@app.route("/nickname")
def set_nickname():
    nick = request.args.get("nick", "")        # SOURCE - stored now, abused later
    conn = _db()
    # Parameterized write: SAFE in isolation. The value is persisted verbatim.
    conn.execute("INSERT INTO prefs(user, nick) VALUES(?, ?)", ("u1", nick))
    conn.commit()
    return "ok"


@app.route("/greet")
def greet():
    conn = _db()
    nick = conn.execute("SELECT nick FROM prefs WHERE user = ?", ("u1",)).fetchone()[0]
    # SINK: the stored (attacker-chosen) nickname is concatenated into SQL.
    return {"rows": conn.execute(
        "SELECT body FROM msg WHERE author = '" + nick + "'").fetchall()}
