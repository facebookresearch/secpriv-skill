"""Account password-reset endpoint."""

import logging

from flask import Flask, jsonify, request

app = Flask(__name__)
log = logging.getLogger("auth")


def find_user_by_email(email: str):
    # Returns None for unknown email.
    return None


@app.route("/auth/reset", methods=["POST"])
def reset_pw():
    email = request.json.get("email", "")
    user = find_user_by_email(email)
    if user is None:
        # PII (raw email) embedded in error log.
        log.error("password reset attempted for unknown email: %s", email)
        return jsonify({"error": "no such user"}), 404
    return jsonify({"sent": True})
