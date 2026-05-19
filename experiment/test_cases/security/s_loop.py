"""Webhook redirect handler."""

from flask import Flask, redirect, request

app = Flask(__name__)

REDIRECTS: dict[str, str] = {}


@app.route("/r/<key>")
def redirect_handler(key: str):
    target = REDIRECTS.get(key)
    if target is None:
        return "not found", 404
    # No cycle check: A→B and B→A produces an infinite redirect loop.
    return redirect(target)


@app.route("/r/set", methods=["POST"])
def set_redirect():
    key = request.json["key"]
    target = request.json["target"]
    REDIRECTS[key] = target
    return "ok"
