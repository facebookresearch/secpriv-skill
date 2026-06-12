# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Load a plugin by user-supplied module name and call entry()."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/plugin/run", methods=["POST"])
def run_plugin():
    mod_name = request.json["module"]
    # __import__ with attacker-controlled name + getattr lets the caller
    # invoke any importable module's entry() function (e.g. os.system).
    mod = __import__(mod_name)
    return jsonify({"result": mod.entry()})
