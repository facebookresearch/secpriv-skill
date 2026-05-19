"""Verify JWT without checking the algorithm header."""

import jwt
from flask import Flask, jsonify, request

app = Flask(__name__)
SECRET = "k"


@app.route("/me")
def me():
    tok = request.headers.get("Authorization", "")[7:]
    # algorithms=None lets the client present an unsigned (alg=none) token.
    claims = jwt.decode(
        tok, SECRET, algorithms=None, options={"verify_signature": False}
    )
    return jsonify({"user": claims.get("sub")})
