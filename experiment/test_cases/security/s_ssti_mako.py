"""Render a user-supplied Mako template."""

from flask import Flask, request
from mako.template import Template

app = Flask(__name__)


@app.route("/mako")
def mako_preview():
    src = request.args.get("src", "")
    # Mako templates execute Python expressions in ${} — RCE if src is
    # attacker-controlled.
    return Template(src).render(name="bob")
