# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Inbound webhook handler — no signature check + payload logged in clear."""

import logging

from flask import Flask, jsonify, request

app = Flask(__name__)
log = logging.getLogger("webhook")


@app.route("/webhook/payment", methods=["POST"])
def payment_webhook():
    # No signature verification — any caller can spoof a payment event.
    body = request.get_json()
    # Full PII payload (customer email + card last4) written to logs.
    log.info("payment webhook received: %s", body)
    return jsonify({"received": True})
