"""Convert user-uploaded image to thumbnail via shell command."""

import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploads"


@app.route("/thumb", methods=["POST"])
def make_thumb():
    filename = request.json.get("filename", "")
    size = request.json.get("size", "200x200")
    out = os.path.join(UPLOAD_DIR, "thumb_" + filename)
    cmd = f"convert {os.path.join(UPLOAD_DIR, filename)} -resize {size} {out}"
    # shell=True with user-controlled filename and size — command injection.
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.returncode != 0:
        return jsonify({"error": "conversion failed"}), 500
    return jsonify({"path": out})
