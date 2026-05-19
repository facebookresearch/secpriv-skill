"""API key sourced from the OS environment."""

import os


# Trusted runtime configuration — env vars are not hardcoded source secrets.
STRIPE_KEY = os.environ["STRIPE_SECRET_KEY"]


def stripe_client():
    return {"key": STRIPE_KEY}
