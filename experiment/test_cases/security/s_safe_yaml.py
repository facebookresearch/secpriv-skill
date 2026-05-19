# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Load user-uploaded YAML config — SafeLoader path."""

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config/load", methods=["POST"])
def load_config():
    text = request.data.decode("utf-8")
    # safe_load disables arbitrary tag execution — no deserialization RCE.
    try:
        cfg = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return jsonify({"error": str(e)}), 400
    if not isinstance(cfg, dict):
        return jsonify({"error": "expected mapping"}), 400
    return jsonify({"loaded": list(cfg.keys())})
