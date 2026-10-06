"""HARD4/SAFE sqli - same cross-file store/read-back shape as the second-order
vuln, but dao binds the read-back value as a query parameter."""
from flask import Flask, request

from store import save, get_latest
from dao import lookup

app = Flask(__name__)


@app.route("/set")
def set_nick():
    nick = request.args.get("nick", "")
    save(nick)
    return "ok"


@app.route("/show")
def show():
    nick = get_latest()
    return {"rows": lookup(nick)}
