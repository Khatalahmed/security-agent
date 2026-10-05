"""Fixture: VULNERABLE — SSTI. Ground truth: one SSTI in `greet`."""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    # User input concatenated into the template SOURCE (not passed as data):
    # /greet?name={{7*7}}  -> 49; Jinja2 SSTI escalating to RCE.
    name = request.args.get("name", "")
    return render_template_string("<p>Welcome, " + name + "!</p>")
