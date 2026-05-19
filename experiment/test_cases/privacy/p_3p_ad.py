# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Ad SDK call carrying the user's IP and email."""

import requests
from flask import Flask, request

app = Flask(__name__)
AD_SDK_URL = "https://ads.example.com/track"


def current_user_email() -> str:
    return "alice@example.org"


@app.route("/page")
def page():
    email = current_user_email()
    ip = request.remote_addr
    # Forwards email and IP — both are PII — to the ad provider.
    requests.post(AD_SDK_URL, json={"email": email, "ip": ip, "event": "page_view"})
    return ""
