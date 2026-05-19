# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Account-creation endpoint that ships data to ML training without consent."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def queue_for_training(record: dict) -> None:
    """Sends the record into the model-training pipeline."""
    # Pretend to queue.
    pass


@app.route("/account/create", methods=["POST"])
def create_account():
    body = request.json
    record = {
        "email": body["email"],
        "name": body.get("name"),
        "country": body.get("country"),
    }
    # No consent check before sending personal data into the training pipeline.
    queue_for_training(record)
    return jsonify({"created": True})
