"""HARD4/SAFE cmdi - same 3-file chain, but the middle builder shlex.quote()s
the user value, so it cannot break out of the command. Sink file is unchanged."""
from flask import Flask, request

from builder import ping_cmd
from runner import run

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return run(ping_cmd(host))
