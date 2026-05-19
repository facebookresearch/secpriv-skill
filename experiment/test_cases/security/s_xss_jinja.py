# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Profile rendering endpoint."""

from flask import Flask, render_template_string, request
from markupsafe import Markup

app = Flask(__name__)

PROFILE_TPL = """
<html><body>
  <h1>Welcome, {{ display_name | safe }}</h1>
  <p>Bio: {{ bio | safe }}</p>
</body></html>
"""


@app.route("/profile")
def profile():
    display_name = request.args.get("name", "Anonymous")
    bio = request.args.get("bio", "")
    # |safe filter on user input bypasses Jinja2 auto-escaping.
    return render_template_string(PROFILE_TPL, display_name=display_name, bio=bio)
