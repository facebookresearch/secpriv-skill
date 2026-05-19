"""SOAP request handler using xml.etree without entity protection."""

import xml.etree.ElementTree as ET

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/soap", methods=["POST"])
def soap():
    body = request.data
    # ET.fromstring uses the default expat parser; while modern Python
    # disables entity expansion by default, the fact that the server
    # accepts raw XML with no schema validation means malicious DTDs
    # ship straight through. This mirrors the historical SOAP XXE pattern.
    tree = ET.fromstring(body)
    return jsonify({"action": tree.find(".//action").text})
