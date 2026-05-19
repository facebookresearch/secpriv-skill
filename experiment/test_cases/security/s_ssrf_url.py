"""Fetch endpoint that proxies an arbitrary user-controlled URL."""

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    target = request.args.get("url", "")
    # No allowlist, no scheme check, no IP-range check — full SSRF.
    r = requests.get(target, timeout=3)
    return jsonify({"status": r.status_code, "body": r.text[:200]})
