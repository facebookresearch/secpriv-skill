# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Nightly export of full user records to a CRM, no minimization."""

import requests


CRM_URL = "https://crm.example.com/sync"


def all_users() -> list[dict]:
    return [
        {"id": 1, "email": "a@example.org", "phone": "+1...", "address": "..."},
        {"id": 2, "email": "b@example.org", "phone": "+1...", "address": "..."},
    ]


def nightly_sync() -> None:
    users = all_users()
    # Pushes the full PII record set to a third party with no anonymization.
    requests.post(CRM_URL, json={"users": users})
