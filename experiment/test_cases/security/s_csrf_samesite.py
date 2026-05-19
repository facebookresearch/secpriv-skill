"""Session cookie set with SameSite=None and no CSRF token."""

from flask import Flask, make_response

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    resp = make_response("ok")
    # SameSite=None allows the cookie to be sent on cross-site requests;
    # combined with no CSRF token, every POST is forgeable.
    resp.set_cookie("session", "abc", samesite="None", secure=True)
    return resp
