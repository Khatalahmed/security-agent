"""HARD / VULNERABLE — IDOR: authentication present, authorization missing.

Ground truth: IDOR. There IS a check — but it only confirms the user is logged
in (authN), never that they OWN the account (authZ). Subtle because a guard
exists; it's just the wrong one.
"""
from flask import Flask, request, jsonify, abort

app = Flask(__name__)


class _Session:
    is_authenticated = True
    id = 42


current_user = _Session()


class _DB:
    def get_account(self, account_id):
        return {"id": account_id, "owner_id": 7, "balance": 9999}


DB = _DB()


@app.route("/account/<account_id>/balance")
def balance(account_id):
    if not current_user.is_authenticated:
        abort(401)                            # authN only — NOT authZ
    acct = DB.get_account(account_id)         # no check acct.owner_id == current_user.id
    return jsonify({"balance": acct["balance"]})
