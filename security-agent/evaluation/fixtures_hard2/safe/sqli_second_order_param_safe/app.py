"""HARD/SAFE - second-order shape, but the read-back value is parameterized.

Ground truth: NO findings. Identical structure to the second-order vuln (store a
user nickname, read it back later, use it in a query), which makes it look just
as suspicious. It is safe because `greet` binds the stored value as a query
parameter instead of concatenating it, so re-introduced data is never SQL text.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def _db():
    return sqlite3.connect("app.db")


@app.route("/nickname")
def set_nickname():
    nick = request.args.get("nick", "")
    conn = _db()
    conn.execute("INSERT INTO prefs(user, nick) VALUES(?, ?)", ("u1", nick))
    conn.commit()
    return "ok"


@app.route("/greet")
def greet():
    conn = _db()
    nick = conn.execute("SELECT nick FROM prefs WHERE user = ?", ("u1",)).fetchone()[0]
    # Bound parameter: the stored value stays data, never query text.
    return {"rows": conn.execute(
        "SELECT body FROM msg WHERE author = ?", (nick,)).fetchall()}
