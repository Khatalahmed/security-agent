"""HARD / VULNERABLE — SSTI where user input builds the template via a helper.

Ground truth: SSTI. The render call itself looks benign; the template SOURCE is
assembled with %-formatting from user input one function away.
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)


def render_banner(msg):
    # Unsafe: user msg becomes part of the template SOURCE.
    tmpl = "<div class='banner'>%s</div>" % msg
    return render_template_string(tmpl)


@app.route("/banner")
def banner():
    return render_banner(request.args.get("msg", ""))
