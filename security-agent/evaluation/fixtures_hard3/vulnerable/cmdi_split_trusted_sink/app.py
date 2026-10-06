"""HARD3/VULN - command injection split across THREE files so that no single
file is alarming on its own. app.py has the SOURCE but no visible sink;
cmd_builder.py just concatenates strings; executor.py runs a command but is
documented as receiving an 'internal, already-validated' line. Only joining all
three (user opts -> build_convert_cmd -> execute -> os.popen) reveals the bug.
"""
from flask import Flask, request

from cmd_builder import build_convert_cmd
from executor import execute

app = Flask(__name__)


@app.route("/convert")
def convert():
    opts = request.args.get("opts", "")          # SOURCE: external, UNvalidated
    return execute(build_convert_cmd(opts))       # user -> builder -> executor
