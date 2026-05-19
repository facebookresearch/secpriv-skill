"""Extract a user-uploaded zip to a directory; vulnerable to zip-slip."""

import os
import zipfile

from flask import Flask, jsonify, request

app = Flask(__name__)
EXTRACT_DIR = "/tmp/extracted"


@app.route("/upload-zip", methods=["POST"])
def upload_zip():
    f = request.files["archive"]
    with zipfile.ZipFile(f) as zf:
        # extractall does not validate member paths; an entry named
        # ../../etc/cron.d/evil escapes EXTRACT_DIR — zip-slip.
        zf.extractall(EXTRACT_DIR)
    return jsonify({"extracted": True})
