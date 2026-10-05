"""Example fixture for the idor skill: object read by user id with no ownership check."""
from flask import Flask, request, jsonify

app = Flask(__name__)


class _DB:
    def get_invoice(self, invoice_id):
        return {"id": invoice_id, "amount": 100, "owner": "someone"}


DB = _DB()


@app.route("/invoice")
def invoice():
    # IDOR: the invoice is fetched purely by the user-supplied id. No check that
    # the current user owns it, and ids are sequential → any user reads any invoice.
    # /invoice?id=1001
    invoice_id = request.args.get("id", "")
    return jsonify(DB.get_invoice(invoice_id))
