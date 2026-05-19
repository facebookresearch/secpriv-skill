"""Deep-link triggered agent action."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def run_agent_action(action: str, params: dict) -> dict:
    """Executes a privileged agent task: file edits, deploys, etc."""
    return {"status": "executed", "action": action}


@app.route("/agent/run")
def agent_run():
    # URL parameter auto-triggers a privileged agent action with no confirmation step.
    action = request.args.get("action", "")
    params = request.args.to_dict()
    result = run_agent_action(action, params)
    return jsonify(result)
