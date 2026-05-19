# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""HTTP fetch with retry-on-error and no maximum-attempt cap."""

import time

import requests


def fetch_until_ok(url: str) -> str:
    while True:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return r.text
        except requests.RequestException:
            pass
        # No retry counter, no exponential backoff cap; can spin indefinitely
        # if the upstream is permanently down.
        time.sleep(1)
