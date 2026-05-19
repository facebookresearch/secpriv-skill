# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User password hashed with MD5."""

import hashlib


def hash_password(plaintext: str) -> str:
    # MD5 is broken for password hashing: fast and unsalted, so rainbow
    # tables and brute-force are trivial.
    return hashlib.md5(plaintext.encode()).hexdigest()


def store_user(email: str, password: str) -> None:
    row = {"email": email, "pw_hash": hash_password(password)}
    _save(row)


def _save(row: dict) -> None:
    pass
