"""Admin user management endpoints."""

from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.route("/api/profile")
@require_auth
def get_profile():
    return jsonify({"id": 1, "name": "test"})


@app.route("/api/admin/delete-user", methods=["POST"])
def admin_delete_user():
    # No @require_auth — any unauthenticated client can delete any user.
    user_id = request.json.get("user_id")
    # ... deletion logic ...
    return jsonify({"deleted": user_id})
