"""Image-by-URL importer — vulnerable to AWS metadata SSRF."""

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/images/import", methods=["POST"])
def import_image():
    src = request.json["src"]
    # Attacker can submit src=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # to exfiltrate cloud-instance IAM credentials.
    data = requests.get(src, timeout=3).content
    return jsonify({"size": len(data)})
