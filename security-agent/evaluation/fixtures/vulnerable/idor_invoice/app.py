"""Fixture: VULNERABLE — IDOR. Ground truth: one IDOR in `get_invoice`."""
from flask import Flask, request, jsonify

app = Flask(__name__)


class _DB:
    def invoice(self, invoice_id):
        return {"id": invoice_id, "amount": 100, "owner": "someone"}


DB = _DB()


@app.route("/invoice")
def get_invoice():
    # Resource fetched purely by user-supplied id, no ownership/authorization
    # check; ids are sequential -> any user reads any invoice. /invoice?id=1001
    invoice_id = request.args.get("id", "")
    return jsonify(DB.invoice(invoice_id))
