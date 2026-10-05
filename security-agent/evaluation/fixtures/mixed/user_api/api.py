"""Fixture: MIXED — one real bug + one correctly-written handler.

Ground truth: exactly ONE finding — command injection in `run_lookup`.
`get_profile` is safe (parameterized) and must NOT be flagged.
"""
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def run_lookup():
    # VULNERABLE: user-controlled `domain` passed to a shell.
    # /lookup?domain=example.com;id
    domain = request.args.get("domain", "")
    out = subprocess.check_output(f"nslookup {domain}", shell=True)
    return out


@app.route("/profile")
def get_profile():
    # SAFE: parameterized query, no interpolation.
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT name, email FROM users WHERE id = ?", (uid,)
    ).fetchone()
    return {"profile": row}
