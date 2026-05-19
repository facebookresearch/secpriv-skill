# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Parse a user-uploaded XML file with default lxml settings."""

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)


@app.route("/xml/parse", methods=["POST"])
def parse_xml():
    blob = request.data
    # Default lxml parser resolves external entities; <!ENTITY x SYSTEM "file:///etc/passwd">
    # exfiltrates local files.
    doc = etree.fromstring(blob)
    return jsonify({"root": doc.tag})
