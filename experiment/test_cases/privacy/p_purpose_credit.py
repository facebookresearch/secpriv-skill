# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Loyalty-program purchase data fed into a credit-scoring model."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def record_purchase(user_id: str, amount: float, items: list) -> None:
    # Collected for: loyalty-points accrual.
    pass


def update_credit_score(user_id: str, history: list) -> None:
    """Recompute internal credit score from purchase history."""
    pass


@app.route("/checkout/done", methods=["POST"])
def checkout_done():
    uid = request.json["user_id"]
    amt = request.json["amount"]
    items = request.json["items"]
    record_purchase(uid, amt, items)
    # Reusing loyalty data for credit decisions is a purpose change.
    update_credit_score(uid, [{"amt": amt, "items": items}])
    return jsonify({"ok": True})
