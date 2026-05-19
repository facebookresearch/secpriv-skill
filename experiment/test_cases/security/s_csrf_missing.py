"""State-changing endpoint with no CSRF token check."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/account/email", methods=["POST"])
def update_email():
    new_email = request.form["email"]
    # No CSRF token verification; an attacker page can submit a hidden
    # form against the victim's session cookie.
    _save_email(new_email)
    return jsonify({"updated": True})


def _save_email(e: str) -> None:
    pass
