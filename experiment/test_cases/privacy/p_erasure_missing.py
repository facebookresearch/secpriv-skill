# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User-account API exposes create/read/update — but no delete endpoint."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/users", methods=["POST"])
def create_user():
    return jsonify({"id": 1})


@app.route("/users/<int:uid>")
def get_user(uid: int):
    return jsonify({"id": uid})


@app.route("/users/<int:uid>", methods=["PUT"])
def update_user(uid: int):
    return jsonify({"id": uid})


# No DELETE handler. GDPR Art. 17 / CCPA §1798.105 require an
# erasure path; this API has no way to honor a deletion request.
