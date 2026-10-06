"""HARD/VULN - SSRF through a generic-looking HTTP helper in another file.

Ground truth: ssrf. The user-supplied `url` flows across a file into get_json(),
a plain "fetch some JSON" utility with no scheme or host restriction. In
isolation httpclient.get_json looks like ordinary plumbing; the forgery only
exists because its argument is attacker-controlled and unvalidated.
"""
from flask import Flask, request

from httpclient import get_json

app = Flask(__name__)


@app.route("/preview")
def preview():
    target = request.args.get("url", "")       # SOURCE: external input
    return get_json(target)                     # flows across files to the sink
