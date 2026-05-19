"""Exception handler dumps the full request, including Authorization header."""

import logging
import traceback

from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger("api")


@app.route("/account")
def account():
    try:
        return _load_account()
    except Exception:
        # request.headers includes Authorization: Bearer <token>; logging
        # them captures bearer tokens in the error log.
        log.error(
            "account error: headers=%s\n%s",
            dict(request.headers),
            traceback.format_exc(),
        )
        return "error", 500


def _load_account():
    raise RuntimeError("db down")
