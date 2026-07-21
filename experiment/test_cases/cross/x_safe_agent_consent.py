# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Authenticated agent action requiring a single-use confirmation token AND consent."""

import secrets

from flask import abort, Flask, jsonify, request

app = Flask(__name__)
DECLARED_DOWNSTREAM = {"https://crm.example.com/sync"}
_PENDING_CONFIRM: dict[str, str] = {}
_CONSENT_GRANTS = {("u1", "crm_sync")}
_SESSIONS: dict[str, str] = {}  # bearer token -> authenticated user_id


def _authed_user() -> str | None:
    tok = request.headers.get("Authorization", "")
    if not tok.startswith("Bearer "):
        return None
    return _SESSIONS.get(tok[7:])


def has_consent(user_id: str, scope: str) -> bool:
    return (user_id, scope) in _CONSENT_GRANTS


def run_agent_action(action: str, target: str) -> dict:
    return {"ok": True}


@app.route("/agent/preview")
def preview_agent_action():
    if _authed_user() is None:
        abort(401)
    # Step 1: issue a single-use, unpredictable confirmation token bound to
    # the session; execution is only possible after echoing it back.
    sid = request.args.get("sid", "")
    token = secrets.token_urlsafe(32)
    _PENDING_CONFIRM[sid] = token
    return jsonify({"preview": request.args.to_dict(), "confirm_token": token})


@app.route("/agent/run", methods=["POST"])
def run_agent_with_confirm():
    # Caller identity comes from the authenticated session, never the body.
    user_id = _authed_user()
    if user_id is None:
        abort(401)
    body = request.json
    expected = _PENDING_CONFIRM.pop(body.get("sid", ""), None)
    if not expected or not secrets.compare_digest(
        body.get("confirm_token", ""), expected
    ):
        abort(400, "missing or invalid confirmation")
    if not has_consent(user_id, body.get("scope", "")):
        abort(403, "no consent")
    target = body.get("target", "")
    if target not in DECLARED_DOWNSTREAM:
        abort(400, "undeclared target")
    return jsonify(run_agent_action(body["action"], target))
