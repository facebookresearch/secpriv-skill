# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Deep-link in an email opens the app and immediately runs an action."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/open")
def open_deep_link():
    action = request.args.get("a", "")
    target = request.args.get("t", "")
    # No interstitial / preview screen — the deep link triggers the action
    # the moment the user opens it from an email.
    return jsonify({"ran": _do(action, target)})


def _do(action: str, target: str) -> str:
    return f"{action}:{target}"
