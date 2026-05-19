"""XML parser configured to disable entity resolution."""

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)
# Parser explicitly disables external entities, DTDs, and network access.
SAFE_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False
)


@app.route("/xml/parse", methods=["POST"])
def parse_xml():
    doc = etree.fromstring(request.data, SAFE_PARSER)
    return jsonify({"root": doc.tag})
