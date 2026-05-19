# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""JWT signing key as a module-level literal."""

import time

import jwt

# Production JWT signing key embedded in source.
JWT_SIGNING_KEY = "WLFZx2-prod-jwt-signing-key-9c91-do-not-commit"


def issue_token(user_id: int) -> str:
    return jwt.encode(
        {"sub": user_id, "iat": int(time.time())}, JWT_SIGNING_KEY, algorithm="HS256"
    )
