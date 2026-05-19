# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Serve user-uploaded files with realpath containment check."""

import os

from flask import abort, Flask, request, send_file

app = Flask(__name__)
UPLOAD_DIR = os.path.realpath("/var/www/uploads")


@app.route("/files/<path:fname>")
def serve_file(fname: str):
    candidate = os.path.realpath(os.path.join(UPLOAD_DIR, fname))
    # Containment check: realpath must remain inside UPLOAD_DIR.
    if not candidate.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    if not os.path.isfile(candidate):
        abort(404)
    return send_file(candidate)
