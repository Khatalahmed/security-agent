"""Example fixture for the ssti skill: SSTI via render_template_string."""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # SSTI: user input is concatenated into the TEMPLATE SOURCE, not passed as data.
    # /hello?name={{7*7}}  renders 49; escalates to RCE in Jinja2.
    return render_template_string("<h1>Hello " + name + "</h1>")
