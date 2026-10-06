"""HARD/VULN - command injection; the SINK helper looks benign in isolation.

Ground truth: command_injection. External input flows from this route ACROSS a
file into exec_report(), which calls a generic-looking _run(cmd). Reading
reporting.py on its own, _run is just "a command runner" and exec_report just
"builds a string" - nothing screams vuln. Only following the taint from the
route (user `format` -> exec_report -> _run -> os.popen) proves it exploitable.
This is the case per-file analysis structurally misses and taint should catch.
"""
from flask import Flask, request

from reporting import exec_report

app = Flask(__name__)


@app.route("/report")
def report():
    fmt = request.args.get("format", "pdf")   # SOURCE: external input
    return exec_report(fmt)                    # flows across files
