"""Example fixture for the secrets skill (and a multi-skill demo).

Contains BOTH a hardcoded secret (for the `secrets` skill) and a command
injection (for `source_audit`), so one audit run exercises both skills.
The AWS value is AWS's official *documentation example* key, not a real secret.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret — the `secrets` skill should flag this.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@app.route("/lookup")
def lookup():
    # Command injection — the `source_audit` skill should flag this.
    host = request.args.get("host", "")
    return subprocess.check_output(f"host {host}", shell=True)
