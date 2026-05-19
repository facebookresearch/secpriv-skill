# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Load a user-uploaded YAML config with the unsafe loader."""

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    text = request.data.decode("utf-8")
    # yaml.load (without SafeLoader) executes arbitrary !!python/object tags.
    cfg = yaml.load(text, Loader=yaml.Loader)
    return jsonify({"keys": list(cfg.keys()) if isinstance(cfg, dict) else None})
