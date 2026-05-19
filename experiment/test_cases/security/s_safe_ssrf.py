# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Image fetcher with explicit URL allowlist and private-IP check."""

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import abort, Flask, jsonify, request

app = Flask(__name__)
ALLOWED_HOSTS = {"images.example.com", "cdn.example.org"}


def _is_safe(url: str) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or p.hostname not in ALLOWED_HOSTS:
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


@app.route("/img/fetch")
def fetch_image():
    url = request.args.get("url", "")
    if not _is_safe(url):
        abort(400)
    r = requests.get(url, timeout=3)
    return jsonify({"size": len(r.content)})
