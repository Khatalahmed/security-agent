"""HARD3/VULN - SSRF split across three files. SOURCE here, URL assembly in
url_builder.py, the actual request in fetcher.py (documented as a 'vetted
endpoint'). No single file shows user-input-reaching-an-unrestricted-fetch.
"""
from flask import Flask, request

from url_builder import build_url
from fetcher import fetch

app = Flask(__name__)


@app.route("/fetch")
def fetch_resource():
    resource = request.args.get("resource", "")   # SOURCE: external, UNvalidated
    return fetch(build_url(resource))              # user -> builder -> fetcher
