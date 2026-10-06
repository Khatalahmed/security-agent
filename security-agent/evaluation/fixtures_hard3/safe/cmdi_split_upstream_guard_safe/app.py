"""HARD3/SAFE - same three-file split as the cmdi vuln, but the input is
validated UPSTREAM here in app.py before it ever reaches the builder/executor.
`opts` is constrained to [a-z0-9_-]+ (no spaces or shell metacharacters), so the
command cannot be broken out of. The executor file is unchanged and still looks
dangerous in isolation - the safety is not visible there.
"""
import re

from flask import Flask, request, abort

from cmd_builder import build_convert_cmd
from executor import execute

app = Flask(__name__)
_SAFE = re.compile(r"\A[a-z0-9_-]+\Z")


@app.route("/convert")
def convert():
    opts = request.args.get("opts", "")
    if not _SAFE.match(opts):                     # UPSTREAM guard: no metacharacters
        abort(400)
    return execute(build_convert_cmd(opts))
