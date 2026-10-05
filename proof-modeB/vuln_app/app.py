"""
Deliberately vulnerable sample Flask app — LOCAL TEST FIXTURE ONLY.
Used to verify that vulnhuntr can detect and report a vulnerability.
Do not deploy. The flaws below are intentional.
"""
import os
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download")
def download():
    # User controls `name`, which is joined into a path with no sanitization.
    # Intentional Local File Inclusion / path traversal: /download?name=../../etc/passwd
    name = request.args.get("name", "")
    base = os.path.join(os.path.dirname(__file__), "files")
    path = os.path.join(base, name)
    return send_file(path)


@app.route("/ping")
def ping():
    # User-controlled host passed straight into a shell command.
    # Intentional command injection / RCE: /ping?host=127.0.0.1;whoami
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output


@app.route("/fetch")
def fetch():
    # User-controlled URL fetched server-side with no allowlist.
    # Intentional SSRF: /fetch?url=http://169.254.169.254/latest/meta-data/
    import requests

    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return resp.text


if __name__ == "__main__":
    app.run(debug=True)
