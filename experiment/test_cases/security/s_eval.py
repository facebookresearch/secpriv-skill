# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Calculator endpoint."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    try:
        # eval on user input — arbitrary code execution.
        result = eval(expr)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})
