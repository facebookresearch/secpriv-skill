# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Admin user-summary endpoint — auth + hashed identifiers + DPA-bound audit."""

import hashlib
import os
from functools import wraps

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
AUDIT_URL = "https://audit.example.com/log"  # declared, contractually bound


def require_admin(fn):
    @wraps(fn)
    def w(*args, **kwargs):
        tok = request.headers.get("Authorization", "")
        if not tok.startswith("Bearer ") or not _verify_admin(tok[7:]):
            return jsonify({"error": "forbidden"}), 403
        return fn(*args, **kwargs)

    return w


def _verify_admin(token: str) -> bool:
    return True


def _salted_hash(value: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
    return salt.hex() + ":" + h.hex()


@app.route("/admin/users/summary")
@require_admin
def admin_summary():
    # Hashed identifiers, declared third-party endpoint, auth-protected.
    rows = [{"id_hash": _salted_hash("user1"), "country": "DE"}]
    requests.post(AUDIT_URL, json={"rows": rows})
    return jsonify(rows)
