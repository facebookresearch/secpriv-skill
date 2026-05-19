"""Calculator endpoint."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    try:
        # eval on user input — arbitrary code execution.
        result = eval(expr)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})
