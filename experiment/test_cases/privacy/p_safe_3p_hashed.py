# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Analytics endpoint receives only a salted hash of the email."""

import hashlib
import os

import requests


ANALYTICS_URL = "https://analytics.example.com/event"


def _salted_hash(value: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
    return salt.hex() + ":" + h.hex()


def track_page_view(email: str, path: str) -> None:
    # Only the salted hash is shared with the third party — no raw PII.
    requests.post(ANALYTICS_URL, json={"id_hash": _salted_hash(email), "path": path})
