"""Render a user comment via Markup(), bypassing Jinja auto-escape."""

from flask import Flask, render_template_string, request
from markupsafe import Markup

app = Flask(__name__)
TPL = "<div class='comment'>{{ content }}</div>"


@app.route("/comment")
def show_comment():
    user_html = request.args.get("c", "")
    # Markup() marks the string as already-safe HTML — Jinja will not escape it.
    return render_template_string(TPL, content=Markup(user_html))
