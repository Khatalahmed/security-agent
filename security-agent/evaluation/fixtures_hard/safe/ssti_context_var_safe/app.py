"""HARD / SAFE — render_template_string used correctly.

Ground truth: NO findings. render_template_string IS called with user input
(looks like SSTI), but the template text is a FIXED constant and the user value
is passed as a bound, autoescaped context variable (data, not source).
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/banner")
def banner():
    msg = request.args.get("msg", "")
    # Fixed template; msg is DATA, not template source. Autoescaped by Jinja2.
    return render_template_string("<div class='banner'>{{ msg }}</div>", msg=msg)
