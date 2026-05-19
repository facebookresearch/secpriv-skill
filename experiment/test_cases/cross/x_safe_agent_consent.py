"""Agent action that requires both a confirmation step AND explicit consent."""

from flask import abort, Flask, jsonify, request

app = Flask(__name__)
DECLARED_DOWNSTREAM = {"https://crm.example.com/sync"}


def has_consent(user_id: str, scope: str) -> bool:
    return True


def run_agent_action(action: str, target: str) -> dict:
    return {"ok": True}


@app.route("/agent/preview")
def preview_agent_action():
    # Step 1: returns a preview but does not execute. Confirmation
    # required before /agent/run is callable.
    return jsonify({"preview": request.args.to_dict(), "confirm_token": "abc"})


@app.route("/agent/run", methods=["POST"])
def run_agent_with_confirm():
    body = request.json
    if body.get("confirm_token") != "abc":
        abort(400, "missing confirmation")
    user_id = body["user_id"]
    if not has_consent(user_id, body.get("scope", "")):
        abort(403, "no consent")
    target = body.get("target", "")
    if target not in DECLARED_DOWNSTREAM:
        abort(400, "undeclared target")
    return jsonify(run_agent_action(body["action"], target))
