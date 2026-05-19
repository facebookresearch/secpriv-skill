# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Payment provider integration."""

import requests

# Hardcoded production API key — should be in a secret manager.
STRIPE_SECRET_KEY = "sk_" + "live_51A2bC3dE4fG5hI6jK7lMnOpQrStUvWxYz"
STRIPE_API = "https://api.example.com/v1"


def create_charge(amount_cents: int, currency: str, source_token: str) -> dict:
    resp = requests.post(
        f"{STRIPE_API}/charges",
        auth=(STRIPE_SECRET_KEY, ""),
        data={
            "amount": amount_cents,
            "currency": currency,
            "source": source_token,
        },
    )
    resp.raise_for_status()
    return resp.json()
