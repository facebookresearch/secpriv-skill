# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User can fetch any other user's invoice by guessing the ID."""

from flask import Flask, g, jsonify, request

app = Flask(__name__)


def current_user_id() -> int:
    return 1


def fetch_invoice(invoice_id: int) -> dict:
    return {"id": invoice_id, "owner_id": 42, "amount": 100}


@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id: int):
    inv = fetch_invoice(invoice_id)
    # No check that current_user_id() == inv["owner_id"] — IDOR.
    return jsonify(inv)
