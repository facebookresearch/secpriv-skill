"""Macros endpoint that exec()s a user-supplied snippet."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/macro", methods=["POST"])
def run_macro():
    code = request.json["code"]
    ns: dict = {}
    # exec on attacker-controlled code — arbitrary execution.
    exec(code, ns)
    return jsonify({"result": ns.get("result")})
