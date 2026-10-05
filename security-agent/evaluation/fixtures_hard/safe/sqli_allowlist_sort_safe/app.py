"""HARD / SAFE — SQL-shaped code that is actually safe.

Ground truth: NO findings. User input IS concatenated into the SQL string (looks
like SQLi), but it is a sort column validated against a fixed allowlist first,
and the data value is bound as a parameter. A naive reader sees '+ sort' and
cries SQLi; the allowlist makes it safe.
"""
import sqlite3

from flask import Flask, request, abort

app = Flask(__name__)
ALLOWED_SORT = {"name", "created_at", "email"}


@app.route("/users")
def users():
    sort = request.args.get("sort", "name")
    status = request.args.get("status", "")
    if sort not in ALLOWED_SORT:
        abort(400)                            # identifier from a fixed allowlist
    conn = sqlite3.connect("app.db")
    # sort is safe (allowlisted identifier); status is bound as a parameter.
    query = "SELECT id, name FROM users WHERE status = ? ORDER BY " + sort
    return {"rows": conn.execute(query, (status,)).fetchall()}
