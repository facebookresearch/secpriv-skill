# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Admin user-export endpoint — auth bypass + PII leakage to third party."""

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
AUDIT_URL = "https://audit.example.com/log"


def all_users() -> list[dict]:
    return [{"id": 1, "email": "a@example.org", "ip": "1.2.3.4"}]


@app.route("/admin/users.json")
def admin_users():
    # Missing authentication — anyone can fetch the user list.
    users = all_users()
    # PII (email + IP) shipped to a third-party audit endpoint.
    requests.post(AUDIT_URL, json={"viewed_by": request.remote_addr, "users": users})
    return jsonify(users)
