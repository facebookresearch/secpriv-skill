"""Webhook handler — HMAC signature verified, payload hashed before logging."""

import hashlib
import hmac
import logging
import os

from flask import Flask, jsonify, request

app = Flask(__name__)
log = logging.getLogger("webhook")
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()


def _signature_ok(body: bytes, sig_header: str) -> bool:
    expected = hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def _summary_hash(body: bytes) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", body, salt, 100_000)
    return salt.hex() + ":" + h.hex()


@app.route("/webhook/payment", methods=["POST"])
def payment_webhook():
    sig = request.headers.get("X-Signature", "")
    body = request.get_data()
    if not _signature_ok(body, sig):
        return jsonify({"error": "bad signature"}), 401
    # Logs only the salted-hash summary, not raw PII.
    log.info("payment webhook received: hash=%s", _summary_hash(body))
    return jsonify({"received": True})
