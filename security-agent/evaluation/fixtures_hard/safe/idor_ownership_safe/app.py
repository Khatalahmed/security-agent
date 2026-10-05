"""HARD / SAFE — access by user-supplied id that IS properly authorized.

Ground truth: NO findings. Nearly identical to the vulnerable version, but it
enforces ownership (acct.owner_id == current_user.id) before returning the
object, so there is no IDOR.
"""
from flask import Flask, request, jsonify, abort

app = Flask(__name__)


class _Session:
    is_authenticated = True
    id = 7


current_user = _Session()


class _DB:
    def get_account(self, account_id):
        return {"id": account_id, "owner_id": 7, "balance": 9999}


DB = _DB()


@app.route("/account/<account_id>/balance")
def balance(account_id):
    if not current_user.is_authenticated:
        abort(401)
    acct = DB.get_account(account_id)
    if acct is None or acct["owner_id"] != current_user.id:
        abort(403)                            # ownership enforced -> safe
    return jsonify({"balance": acct["balance"]})
