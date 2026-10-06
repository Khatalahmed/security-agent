"""HARD/SAFE - same cross-file shape as the cmdi vuln, but defended.

Ground truth: NO findings. The route passes user input to exec_report across a
file exactly like the vulnerable twin, and the helper really does run a program
with that value - so a taint graph WILL propose this chain and a jumpy reader
cries RCE. It is safe: the helper uses argv list form with shell=False, so the
user value is a single non-shell argument and cannot inject a command.
"""
from flask import Flask, request

from reporting import exec_report

app = Flask(__name__)


@app.route("/report")
def report():
    fmt = request.args.get("format", "pdf")   # external input, but see helper
    return exec_report(fmt)
