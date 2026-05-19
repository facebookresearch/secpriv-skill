"""Registration email used for password reset — same purpose (account access)."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def find_user_by_email(email: str):
    return {"email": email}


def send_reset_email(email: str, token: str) -> None:
    pass


@app.route("/auth/reset", methods=["POST"])
def reset_pw():
    email = request.json["email"]
    user = find_user_by_email(email)
    if user is None:
        return jsonify({"sent": False}), 404
    # Same purpose for which the email was originally collected
    # (account-access correspondence) — not purpose creep.
    token = "abc123"
    send_reset_email(email, token)
    return jsonify({"sent": True})
