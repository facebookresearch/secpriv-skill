"""User profile bio is stored, then later concatenated into a raw analytics
query AND surfaced to a public dashboard — second-order SQLi + PII leakage."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/profile/bio", methods=["POST"])
def save_bio():
    body = request.json
    sqlite3.connect("app.db").execute(
        "UPDATE users SET bio=?, email=? WHERE id=?",
        (body["bio"], body["email"], body["user_id"]),
    )
    return jsonify({"ok": True})


@app.route("/admin/users")
def admin_users():
    conn = sqlite3.connect("app.db")
    row = conn.execute("SELECT bio, email FROM users WHERE id=1").fetchone()
    stored_bio, stored_email = row[0], row[1]
    # Stored bio reused in a raw query — second-order SQL injection,
    # AND the email is returned to the dashboard in clear text — PII leakage.
    stats = conn.execute(
        "SELECT COUNT(*) FROM activity WHERE tag='" + stored_bio + "'"
    ).fetchone()
    return jsonify({"email": stored_email, "activity": stats[0]})
