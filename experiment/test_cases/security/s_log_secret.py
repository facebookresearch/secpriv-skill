# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""API key logged on every request."""

import logging

from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger("api")


@app.route("/v1/data")
def get_data():
    api_key = request.headers.get("X-API-Key", "")
    # API key written into application logs — logs are commonly persisted
    # to less-protected backends.
    log.info("request received api_key=%s", api_key)
    return ""
