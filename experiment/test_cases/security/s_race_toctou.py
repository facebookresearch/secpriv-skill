# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""TOCTOU file existence check followed by open."""

import os


def write_unique(path: str, data: str) -> None:
    # Time-of-check (exists?) is separate from time-of-use (open).
    # Between the two, an attacker can create a symlink to /etc/cron.d.
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(data)
