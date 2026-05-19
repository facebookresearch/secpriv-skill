"""User-uploaded session blob deserializer."""

import base64
import pickle

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/restore-session", methods=["POST"])
def restore_session():
    blob_b64 = request.json.get("session_blob", "")
    blob = base64.b64decode(blob_b64)
    # Deserializing attacker-controlled bytes — RCE via pickle.
    session = pickle.loads(blob)
    return jsonify({"user_id": session.get("user_id")})
