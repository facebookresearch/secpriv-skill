# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User search endpoint."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()
    # Build query string with f-string; passes user input directly.
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"
    cur.execute(query)
    rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run()
