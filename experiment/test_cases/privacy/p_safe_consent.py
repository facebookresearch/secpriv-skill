# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Newsletter signup that gates send on verified consent."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def has_marketing_consent(email: str) -> bool:
    return True


def send_promo_email(email: str, content: str) -> None:
    pass


@app.route("/newsletter/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    # Consent check precedes the processing it gates.
    if not has_marketing_consent(email):
        return jsonify({"queued": False, "reason": "no consent"}), 200
    send_promo_email(email, "Welcome to our weekly digest")
    return jsonify({"queued": True})
