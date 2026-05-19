# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User search via .format() SQL."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/items/search")
def search_items():
    tag = request.args.get("tag", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # .format() interpolation directly into SQL — same vulnerability as f-string.
    query = "SELECT id, name FROM items WHERE tag = '{}'".format(tag)
    cur.execute(query)
    return jsonify(cur.fetchall())
