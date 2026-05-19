"""Tail a log via os.popen with user-controlled filename."""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/logs/tail")
def tail_log():
    name = request.args.get("name", "app")
    # os.popen passes the string to a shell — command injection via name.
    with os.popen("tail -n 50 /var/log/" + name + ".log") as p:
        return jsonify({"output": p.read()})
