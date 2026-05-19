"""Render a user-provided greeting into HTML via string.Template."""

from string import Template

from flask import Flask, request, Response

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # Direct substitution into HTML body with no escaping.
    html = Template("<html><body><h1>Hello, $name!</h1></body></html>").substitute(
        name=name
    )
    return Response(html, mimetype="text/html")
