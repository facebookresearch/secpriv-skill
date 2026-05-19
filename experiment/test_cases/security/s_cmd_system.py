# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Trigger a backup via os.system with user input."""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/backup")
def backup():
    target = request.args.get("target", "default")
    # os.system delegates to /bin/sh — target=foo;rm -rf / executes rm.
    rc = os.system("rsync -a /data /backup/" + target)
    return jsonify({"rc": rc})
