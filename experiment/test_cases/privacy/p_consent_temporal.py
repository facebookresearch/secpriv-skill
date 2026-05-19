"""Newsletter signup with consent check located AFTER the send."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def send_promo_email(email: str, content: str) -> None:
    pass


def has_marketing_consent(email: str) -> bool:
    return True


@app.route("/newsletter/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    # Send happens BEFORE the consent check — temporal ordering bug.
    send_promo_email(email, "Welcome to our weekly digest")
    if not has_marketing_consent(email):
        return jsonify({"queued": False, "reason": "no consent"}), 200
    return jsonify({"queued": True})
