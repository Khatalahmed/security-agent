"""HARD3/VULN - SQL injection split across three files. SOURCE here, SQL text
built in query_builder.py, executed in dao.py (documented as receiving an
'internally built' statement). The concat and the execute live in different
files, and the execute file looks like neutral data-access plumbing.
"""
from flask import Flask, request

from query_builder import build_lookup
from dao import run_query

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    username = request.args.get("username", "")    # SOURCE: external, UNvalidated
    return {"rows": run_query(build_lookup(username))}
