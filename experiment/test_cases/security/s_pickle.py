# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User-uploaded session blob deserializer."""

import base64
import pickle

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    blob_b64 = request.json.get("session_blob", "")
    blob = base64.b64decode(blob_b64)
    # Deserializing attacker-controlled bytes — RCE via pickle.
    session = pickle.loads(blob)
    return jsonify({"user_id": session.get("user_id")})
