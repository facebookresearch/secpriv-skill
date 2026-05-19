"""Webhook test endpoint that follows a user-supplied URL with no scheme filter."""

import urllib.request

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/webhook/test", methods=["POST"])
def test_webhook():
    url = request.json["url"]
    # urllib.request.urlopen accepts file:// — attacker can read local files
    # via file:///etc/passwd.
    with urllib.request.urlopen(url, timeout=3) as r:
        return jsonify({"head": r.read(200).decode("utf-8", "replace")})
