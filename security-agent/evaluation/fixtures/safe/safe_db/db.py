"""Fixture: SAFE — database access done correctly.

Ground truth: NO findings. The query uses a parameterized placeholder, so user
input is never concatenated into SQL.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def find_user():
    # Parameterized query: `name` is bound, not interpolated.
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute(
        "SELECT id, email FROM users WHERE name = ?", (name,)
    ).fetchall()
    return {"rows": rows}
