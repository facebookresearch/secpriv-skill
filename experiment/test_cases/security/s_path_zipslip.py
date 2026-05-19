# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Extract a user-uploaded zip to a directory; vulnerable to zip-slip."""

import os
import zipfile

from flask import Flask, jsonify, request

app = Flask(__name__)
EXTRACT_DIR = "/tmp/extracted"


@app.route("/upload-zip", methods=["POST"])
def upload_zip():
    f = request.files["archive"]
    with zipfile.ZipFile(f) as zf:
        # extractall does not validate member paths; an entry named
        # ../../etc/cron.d/evil escapes EXTRACT_DIR — zip-slip.
        zf.extractall(EXTRACT_DIR)
    return jsonify({"extracted": True})
