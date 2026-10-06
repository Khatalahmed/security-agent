"""HARD4/VULN sqli - second-order across files. /set stores the nickname with a
bound parameter (safe write); /show reads it back and dao concatenates it. The
tainting input and the sink are in different handlers AND different files, so a
source->sink chain walk cannot connect them - only a reader who knows the stored
value is attacker-controlled sees it. (Expected to expose a taint-engine blind
spot vs. the broad per-file reader.)"""
from flask import Flask, request

from store import save, get_latest
from dao import lookup

app = Flask(__name__)


@app.route("/set")
def set_nick():
    nick = request.args.get("nick", "")        # SOURCE, stored now
    save(nick)
    return "ok"


@app.route("/show")
def show():
    nick = get_latest()                         # re-enters as "trusted" DB data
    return {"rows": lookup(nick)}
