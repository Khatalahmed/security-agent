"""HARD4/VULN path traversal - '..' checked on the ENCODED value here; the
reader decodes afterwards, so %2e%2e%2f bypasses."""
from flask import Flask, request, abort

from reader import read

app = Flask(__name__)


@app.route("/doc")
def doc():
    name = request.args.get("name", "")        # SOURCE, URL-encoded
    if ".." in name:                            # check on encoded value
        abort(400)
    return read(name)
