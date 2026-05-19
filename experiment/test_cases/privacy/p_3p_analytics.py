# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Page-view tracker forwards raw email to a third-party analytics SDK."""

import requests
from flask import Flask, request

app = Flask(__name__)
ANALYTICS_URL = "https://analytics.example.com/track"


def get_current_user_email() -> str:
    return "user@example.org"


@app.route("/page-view")
def page_view():
    path = request.args.get("path", "/")
    user_email = get_current_user_email()
    # Sends raw email (PII) to a third-party endpoint without anonymization.
    requests.post(
        ANALYTICS_URL,
        json={"event": "page_view", "path": path, "user_email": user_email},
    )
    return "ok"
