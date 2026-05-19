"""User-supplied format string interpolated against a real object."""

from flask import Flask, request

app = Flask(__name__)


class Settings:
    api_key = "sk_live_real"


SETTINGS = Settings()


@app.route("/fmt")
def fmt():
    spec = request.args.get("fmt", "")
    # str.format with user-controlled format spec lets the caller walk
    # attribute chains: spec="{0.api_key}" leaks the secret.
    return spec.format(SETTINGS)
