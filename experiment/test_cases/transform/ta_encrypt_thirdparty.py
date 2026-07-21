# Copyright (c) Meta Platforms, Inc. and affiliates.

import os

import requests
from cryptography.fernet import Fernet

_partner = Fernet(os.environ["PARTNER_KMS_KEY"].encode())


def sync_profile(profile: dict) -> None:
    # encrypted for the recipient before leaving our boundary
    blob = _partner.encrypt(str(profile).encode())
    requests.post("https://partner.example.com/ingest", data=blob)  # <<SINK
