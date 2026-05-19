# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Recursive directory listing without a depth bound."""

import os


def list_all(path: str) -> list:
    out = []
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        # No depth limit and no symlink check — symlink loops produce
        # unbounded recursion until the stack overflows.
        if os.path.isdir(full):
            out.extend(list_all(full))
        else:
            out.append(full)
    return out
