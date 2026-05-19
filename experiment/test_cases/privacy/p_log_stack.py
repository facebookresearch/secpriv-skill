# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Stack trace exposes user email in 5xx response body."""

import traceback

from flask import Flask, jsonify, request

app = Flask(__name__)


def find_user(email: str) -> dict:
    raise KeyError("not found: " + email)


@app.route("/lookup")
def lookup():
    email = request.args.get("email", "")
    try:
        return jsonify(find_user(email))
    except Exception:
        # The KeyError repr embeds the email; returning the trace to the
        # client leaks PII into the user-visible response.
        return jsonify({"trace": traceback.format_exc()}), 500
