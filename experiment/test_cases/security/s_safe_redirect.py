"""Login post-redirect with a fixed allowlist of next-URL names."""

from flask import abort, Flask, redirect, request, url_for

app = Flask(__name__)
ALLOWED_NEXT = {"home", "profile", "settings"}


@app.route("/login")
def login():
    next_name = request.args.get("next", "home")
    if next_name not in ALLOWED_NEXT:
        abort(400)
    # url_for resolves to a server-defined route — no open redirect.
    return redirect(url_for(next_name))
