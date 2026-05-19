# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""API key sourced from the OS environment."""

import os


# Trusted runtime configuration — env vars are not hardcoded source secrets.
STRIPE_KEY = os.environ["STRIPE_SECRET_KEY"]


def stripe_client():
    return {"key": STRIPE_KEY}
