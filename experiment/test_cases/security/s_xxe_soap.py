# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""SOAP request handler that parses XML with external entities enabled."""

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)


@app.route("/soap", methods=["POST"])
def soap():
    body = request.data
    # Parser explicitly resolves external entities and allows network
    # access, so a malicious DTD in the SOAP body can read local files
    # (file:///etc/passwd) or trigger SSRF — a genuine XXE.
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    tree = etree.fromstring(body, parser)
    return jsonify({"action": tree.findtext(".//action")})
