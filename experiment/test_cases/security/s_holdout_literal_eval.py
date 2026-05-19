# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Parse a user-supplied literal with ast.literal_eval, not eval."""

import ast

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/parse")
def parse():
    text = request.args.get("v", "0")
    # ast.literal_eval only evaluates Python literal structures (numbers,
    # strings, tuples, lists, dicts, booleans, None) — no code execution.
    try:
        v = ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return jsonify({"error": "bad literal"}), 400
    return jsonify({"value": str(v)})
