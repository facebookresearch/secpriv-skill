# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""XML processor that explicitly resolves XInclude on user input."""

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)


@app.route("/xml/process", methods=["POST"])
def process():
    blob = request.data
    doc = etree.fromstring(blob)
    # Explicit XInclude processing on attacker-controlled XML — the
    # included href can be a local file path.
    doc.xinclude()
    return jsonify({"merged": etree.tostring(doc).decode()[:200]})
