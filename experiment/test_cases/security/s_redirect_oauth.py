# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""OAuth callback that does not validate `state` and trusts `redirect_uri`."""

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/oauth/cb")
def oauth_callback():
    code = request.args.get("code")
    redirect_uri = request.args.get("redirect_uri", "/")
    # No `state` validation against session, no allowlist on redirect_uri.
    _exchange_code(code)
    return redirect(redirect_uri)


def _exchange_code(code):
    return None
