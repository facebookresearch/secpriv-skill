# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Stored profile URL later used as an outbound request — stored SSRF."""

import sqlite3

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/profile/url", methods=["POST"])
def set_profile_url():
    url = request.json["avatar_url"]
    conn = sqlite3.connect("app.db")
    conn.execute("UPDATE profile SET avatar_url=? WHERE id=1", (url,))
    return jsonify({"ok": True})


@app.route("/avatar/preview")
def preview():
    conn = sqlite3.connect("app.db")
    stored_url = conn.execute("SELECT avatar_url FROM profile WHERE id=1").fetchone()[0]
    # Server fetches the stored URL — attacker can point it at internal services.
    return jsonify({"data": requests.get(stored_url, timeout=3).text[:200]})
