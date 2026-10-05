"""Fixture: VULNERABLE — SSRF. Ground truth: one SSRF in `proxy`."""
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    # User-controlled URL fetched server-side with no allowlist/validation:
    # /proxy?url=http://169.254.169.254/latest/meta-data/
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text
