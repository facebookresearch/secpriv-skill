# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Convert image to thumbnail using list-arg subprocess (no shell)."""

import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploads"
SIZE_RE = re.compile(r"^\d{1,4}x\d{1,4}$")


@app.route("/thumb", methods=["POST"])
def make_thumb():
    filename = request.json.get("filename", "")
    size = request.json.get("size", "200x200")
    if not SIZE_RE.match(size):
        return jsonify({"error": "bad size"}), 400
    if "/" in filename or ".." in filename:
        return jsonify({"error": "bad filename"}), 400
    src = os.path.join(UPLOAD_DIR, filename)
    out = os.path.join(UPLOAD_DIR, "thumb_" + filename)
    # List-arg subprocess.run with shell=False — no command injection.
    subprocess.run(["convert", src, "-resize", size, out], check=True)
    return jsonify({"path": out})
