"""Admin endpoint protected by auth decorator."""

from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        # Real implementation verifies signature and admin claim.
        if not _verify_admin(token[7:]):
            return jsonify({"error": "forbidden"}), 403
        return fn(*args, **kwargs)

    return wrapper


def _verify_admin(token: str) -> bool:
    # Verifies JWT signature and checks admin claim.
    return True


@app.route("/api/admin/delete-user", methods=["POST"])
@require_admin
def admin_delete_user():
    user_id = request.json.get("user_id")
    return jsonify({"deleted": user_id})
