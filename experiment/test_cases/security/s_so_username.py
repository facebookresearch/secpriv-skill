# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Stored username later used in a raw query."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    name = request.json["name"]
    conn = sqlite3.connect("app.db")
    conn.execute("INSERT INTO users(name) VALUES(?)", (name,))
    conn.commit()
    return jsonify({"ok": True})


@app.route("/admin/lookup")
def admin_lookup():
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT name FROM users LIMIT 1").fetchone()
    stored_name = row[0]
    # Stored attacker-controlled name pasted into a raw query — second-order SQLi.
    return jsonify(
        conn.execute("SELECT * FROM audit WHERE who='" + stored_name + "'").fetchall()
    )
