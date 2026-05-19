# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User profile sync to a non-adequacy-decision country."""

import requests


def sync_profile(user: dict) -> None:
    # The destination country has no GDPR adequacy decision and the
    # transfer relies on no documented safeguards. Art. 45 violation.
    requests.post("https://api.example-no-adequacy.com/users", json=user)


def on_user_update(user: dict) -> None:
    sync_profile(user)
