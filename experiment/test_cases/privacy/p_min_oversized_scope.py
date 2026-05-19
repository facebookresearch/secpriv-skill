# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Newsletter signup requests scope=full_profile but only needs email."""

from flask import Flask, redirect, request

app = Flask(__name__)
OAUTH_URL = "https://auth.example.com/authorize"


@app.route("/newsletter/connect")
def connect_newsletter():
    # The newsletter only sends to the user's email; requesting
    # full_profile + contacts + calendar scopes is over-collection.
    url = (
        f"{OAUTH_URL}?client_id=app"
        "&scope=email%20full_profile%20contacts%20calendar"
        "&response_type=code"
    )
    return redirect(url)
