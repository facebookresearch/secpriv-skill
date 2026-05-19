# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Email-only subscription endpoint that collects far more than necessary."""

from flask import Flask, jsonify, request

app = Flask(__name__)


SUBSCRIBERS: list[dict] = []


@app.route("/subscribe", methods=["POST"])
def subscribe():
    body = request.json
    # Endpoint only needs email to send the digest, but collects and stores
    # name, full address, date_of_birth, phone, and government ID.
    record = {
        "email": body["email"],
        "name": body.get("name"),
        "address": body.get("address"),
        "date_of_birth": body.get("date_of_birth"),
        "phone": body.get("phone"),
        "government_id": body.get("government_id"),
    }
    SUBSCRIBERS.append(record)
    return jsonify({"subscribed": True})
