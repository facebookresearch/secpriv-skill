# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Stored value re-used through the ORM, not raw SQL (admin-authenticated)."""

import hmac
import os
from functools import wraps

from flask import Flask, jsonify, request
from sqlalchemy import Column, create_engine, Integer, select, String
from sqlalchemy.orm import declarative_base, Session

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String)


class Audit(Base):
    __tablename__ = "audit"
    id = Column(Integer, primary_key=True)
    who = Column(String)


engine = create_engine("sqlite:///app.db")
app = Flask(__name__)
ADMIN_TOKEN = os.environ["ADMIN_API_TOKEN"]


def require_admin(fn):
    @wraps(fn)
    def w(*a, **kw):
        tok = request.headers.get("Authorization", "")
        if not (
            tok.startswith("Bearer ") and hmac.compare_digest(tok[7:], ADMIN_TOKEN)
        ):
            return jsonify({"error": "forbidden"}), 403
        return fn(*a, **kw)

    return w


@app.route("/admin/audit/<int:user_id>")
@require_admin
def lookup_audit(user_id: int):
    with Session(engine) as s:
        user = s.get(User, user_id)
        # Stored user.name passed through ORM where() — parameterized; no
        # second-order SQL injection. Endpoint is admin-authenticated.
        rows = s.execute(select(Audit).where(Audit.who == user.name)).scalars().all()
        return jsonify([{"id": r.id, "who": r.who} for r in rows])
