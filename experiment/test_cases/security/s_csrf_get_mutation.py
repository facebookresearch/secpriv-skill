"""Account-deletion exposed on a GET endpoint."""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/account/delete")
def delete_account():
    user_id = request.args.get("uid")
    # GET endpoint that mutates server state — any <img src="..."> tag in
    # an attacker page deletes the victim's account.
    _delete_user(user_id)
    return jsonify({"deleted": user_id})


def _delete_user(uid: str) -> None:
    pass
