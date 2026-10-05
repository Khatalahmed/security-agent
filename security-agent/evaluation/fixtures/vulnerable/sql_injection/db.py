"""Fixture: VULNERABLE — SQL injection.

Ground truth: one high-severity SQLi in `find_user` (string-formatted query).
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def find_user():
    # User input is formatted directly into the SQL string:
    # /user?name=' OR '1'='1  -> authentication/row-filter bypass.
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    query = "SELECT id, email FROM users WHERE name = '%s'" % name
    rows = conn.execute(query).fetchall()
    return {"rows": rows}
