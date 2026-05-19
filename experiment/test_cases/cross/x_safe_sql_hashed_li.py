"""Fraud-detection lookup using parameterized SQL and salted-hash response
under documented legitimate interest."""

import hashlib
import os

from flask import Flask, jsonify, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("postgresql://app@db/app")
# Legitimate-interest assessment on file: docs/privacy/lia-fraud-2024.pdf.
LIA_REF = "docs/privacy/lia-fraud-2024.pdf"


def _salted_hash(value: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
    return salt.hex() + ":" + h.hex()


@app.route("/fraud/check")
def fraud_check():
    ip = request.args.get("ip", "")
    with engine.connect() as conn:
        # Parameterized query — no SQLi.
        rows = conn.execute(
            text("SELECT user_id FROM logins WHERE ip = :ip LIMIT 5"),
            {"ip": ip},
        ).fetchall()
    # Hashed user IDs returned — no raw PII.
    return jsonify(
        {
            "matches": [_salted_hash(str(r[0])) for r in rows],
            "lawful_basis": LIA_REF,
        }
    )
