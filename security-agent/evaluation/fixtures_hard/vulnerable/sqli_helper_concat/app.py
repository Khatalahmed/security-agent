"""HARD / VULNERABLE — SQLi where the unsafe concatenation is in a helper.

Ground truth: SQLi. The handler looks clean; the injection is one call away in
_build_query. Requires following the data across functions (same file).
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


def _build_query(name):
    # Unsafe: user value concatenated into SQL text.
    return "SELECT id, email FROM users WHERE name = '" + name + "'"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    query = _build_query(name)               # taint flows through here
    return {"rows": conn.execute(query).fetchall()}
