# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Serve user-uploaded files."""

from flask import abort, Flask, send_file

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"


@app.route("/files/<path:fname>")
def serve_file(fname: str):
    # Concatenates user input directly into a filesystem path — no realpath check.
    full_path = UPLOAD_DIR + "/" + fname
    try:
        return send_file(full_path)
    except FileNotFoundError:
        abort(404)
