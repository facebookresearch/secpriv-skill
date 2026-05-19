# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Marketing email send with the consent check commented out."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def has_marketing_consent(email: str) -> bool:
    return True


def send_marketing(email: str, body: str) -> None:
    pass


@app.route("/marketing/send", methods=["POST"])
def send():
    email = request.json["email"]
    # if not has_marketing_consent(email):    # TODO re-enable after migration
    #     return jsonify({"queued": False}), 200
    send_marketing(email, "Big sale today!")
    return jsonify({"queued": True})
