"""Newsletter signup collects only email and a coarse country code."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/newsletter/signup", methods=["POST"])
def signup():
    body = request.json
    # Only what is strictly necessary for the digest delivery and
    # localization. No name, no address, no DOB.
    record = {"email": body["email"], "country": body.get("country", "")}
    _save(record)
    return jsonify({"subscribed": True})


def _save(rec: dict) -> None:
    pass
