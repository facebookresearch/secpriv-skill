"""Login post-redirect that honours an arbitrary `next` URL."""

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login")
def login():
    next_url = request.args.get("next", "/")
    # Attacker sends victims to /login?next=https://evil.example.com/phish.
    return redirect(next_url)
