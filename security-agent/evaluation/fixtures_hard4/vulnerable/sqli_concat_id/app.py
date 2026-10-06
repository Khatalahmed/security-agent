"""HARD4/VULN sqli - id concatenated as a string (contrast: safe twin int()s it)."""
from flask import Flask, request

from dao import by_id

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id", "")           # SOURCE (string, unvalidated)
    return {"rows": by_id(uid)}
