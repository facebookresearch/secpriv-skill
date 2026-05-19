"""Render a user-supplied Jinja template string directly."""

from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/preview")
def preview():
    tpl = request.args.get("tpl", "")
    # Attacker template can read globals via {{ config }} or run code via
    # the Jinja sandbox-escape pattern — server-side template injection.
    return Template(tpl).render(user="alice")
