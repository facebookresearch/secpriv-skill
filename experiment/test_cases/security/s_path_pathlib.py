# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Serve a user-asset via pathlib without containment check."""

from pathlib import Path

from flask import abort, Flask, request, send_file

app = Flask(__name__)
ASSETS = Path("/srv/assets")


@app.route("/asset")
def asset():
    name = request.args.get("name", "")
    # Path / user — no resolution check; ../../etc/passwd escapes ASSETS.
    target = ASSETS / name
    if not target.exists():
        abort(404)
    return send_file(str(target))
