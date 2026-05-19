"""Inbound webhook auto-runs an agent task with no confirmation."""

from flask import Flask, jsonify, request

app = Flask(__name__)


def run_agent(task: dict) -> dict:
    return {"ok": True, "task": task["name"]}


@app.route("/wh/agent", methods=["POST"])
def webhook_agent():
    task = request.get_json()
    # Webhook payload directly drives a privileged agent action without
    # any inline confirmation step or sign-off field.
    return jsonify(run_agent(task))
