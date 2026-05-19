# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""SQLAlchemy raw text() with user input."""

from flask import Flask, jsonify, request
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")
app = Flask(__name__)


@app.route("/orders")
def list_orders():
    status = request.args.get("status", "open")
    with engine.connect() as conn:
        # text() with user input concatenation defeats the ORM's parameterization.
        stmt = text("SELECT * FROM orders WHERE status = '" + status + "'")
        rows = conn.execute(stmt).fetchall()
        return jsonify([dict(r._mapping) for r in rows])
