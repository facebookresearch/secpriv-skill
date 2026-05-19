# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Stored notification template later rendered as Jinja — stored SSTI."""

import sqlite3

from flask import Flask, jsonify, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/templates", methods=["POST"])
def save_tpl():
    tpl = request.json["template"]
    sqlite3.connect("app.db").execute("INSERT INTO tpl(body) VALUES(?)", (tpl,))
    return jsonify({"ok": True})


@app.route("/render/<int:tid>")
def render(tid: int):
    row = (
        sqlite3.connect("app.db")
        .execute("SELECT body FROM tpl WHERE id=?", (tid,))
        .fetchone()
    )
    # Stored attacker-controlled template body rendered with full Jinja
    # context — server-side template injection (stored variant).
    return Template(row[0]).render(user="alice", admin=True)
