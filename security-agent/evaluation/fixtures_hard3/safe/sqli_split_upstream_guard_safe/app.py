"""HARD3/SAFE - same three-file SQLi split. The builder still concatenates
(looks like SQLi in isolation) and dao.execute runs a raw string, but `username`
is validated UPSTREAM here to be strictly alphanumeric, so it cannot contain a
quote or any SQL metacharacter. A per-file reader of query_builder.py sees '+ username'
and cries SQLi, missing the guard that lives here.
"""
from flask import Flask, request, abort

from query_builder import build_lookup
from dao import run_query

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    username = request.args.get("username", "")
    if not username.isalnum():                    # UPSTREAM guard: no quotes/metachars
        abort(400)
    return {"rows": run_query(build_lookup(username))}
