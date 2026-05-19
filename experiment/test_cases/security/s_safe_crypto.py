# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Password hashing with bcrypt and a per-record salt."""

import bcrypt


def hash_password(plaintext: str) -> bytes:
    # bcrypt.gensalt() generates a per-record random salt; bcrypt.hashpw
    # is intentionally slow and resistant to rainbow tables.
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12))


def check_password(plaintext: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(plaintext.encode(), stored_hash)
