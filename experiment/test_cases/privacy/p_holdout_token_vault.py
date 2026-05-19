# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Customer ID is tokenized via a vault before use in analytics."""

import requests


ANALYTICS_URL = "https://analytics.example.com/event"
VAULT_URL = "https://vault.example.internal/tokenize"


def _tokenize(customer_id: str) -> str:
    # The vault returns an irreversible token; only authorized callers
    # holding the vault key can de-tokenize.
    return requests.post(
        VAULT_URL, json={"id": customer_id}, headers={"X-Vault-Auth": "..."}
    ).json()["token"]


def track_event(customer_id: str, event: str) -> None:
    requests.post(ANALYTICS_URL, json={"token": _tokenize(customer_id), "event": event})
