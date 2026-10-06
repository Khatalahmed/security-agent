"""HARD4/SAFE sqli - the id is coerced to int() UPSTREAM, so it cannot carry any
SQL metacharacter by the time dao concatenates it. dao is unchanged-looking."""
from flask import Flask, request, abort

from dao import by_id

app = Flask(__name__)


@app.route("/user")
def user():
    try:
        uid = int(request.args.get("id", ""))   # UPSTREAM guard: int() coercion
    except ValueError:
        abort(400)
    return {"rows": by_id(uid)}
