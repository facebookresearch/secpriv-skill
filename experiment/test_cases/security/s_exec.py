# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Macros endpoint that exec()s a user-supplied snippet."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/macro", methods=["POST"])
def run_macro():
    code = request.json["code"]
    ns: dict = {}
    # exec on attacker-controlled code — arbitrary execution.
    exec(code, ns)
    return jsonify({"result": ns.get("result")})
