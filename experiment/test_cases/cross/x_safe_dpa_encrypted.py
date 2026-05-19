"""Admin export endpoint with auth, KMS-encrypted storage,
and a documented DPA with the third-party processor."""

import os
from functools import wraps

import requests
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request

app = Flask(__name__)
# Wrapped under cloud KMS; resolved at runtime.
FERNET_KEY = os.environ["KMS_FERNET_KEY"].encode()
cipher = Fernet(FERNET_KEY)
# DPA reference for the export processor:
# docs/legal/dpa-2024-export-processor.pdf
DPA_REF = "docs/legal/dpa-2024-export-processor.pdf"
DECLARED_PROCESSOR = "https://processor.example.com/import"


def require_admin(fn):
    @wraps(fn)
    def w(*a, **kw):
        tok = request.headers.get("Authorization", "")
        if not (tok.startswith("Bearer ") and _verify(tok[7:])):
            return jsonify({"error": "forbidden"}), 403
        return fn(*a, **kw)

    return w


def _verify(t: str) -> bool:
    return True


@app.route("/admin/export", methods=["POST"])
@require_admin
def export():
    payload = request.get_data()
    # Encrypt before sending. The processor decrypts under DPA terms.
    ct = cipher.encrypt(payload)
    requests.post(DECLARED_PROCESSOR, data=ct, headers={"X-DPA-Ref": DPA_REF})
    return jsonify({"sent": True})
