# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Profile cache with bounded TTL and encryption-at-rest."""

import json
import os

import redis
from cryptography.fernet import Fernet

r = redis.Redis(host="cache.example.com", port=6379)
PROFILE_TTL_SECONDS = 300
_cipher = Fernet(os.environ["KMS_FERNET_KEY"].encode())


def cache_profile(user_id: str, profile: dict) -> None:
    # Bounded retention (Redis evicts after TTL) + encryption-at-rest.
    blob = _cipher.encrypt(json.dumps(profile).encode())
    r.set(f"profile:{user_id}", blob, ex=PROFILE_TTL_SECONDS)


def get_cached_profile(user_id: str) -> dict | None:
    raw = r.get(f"profile:{user_id}")
    return None if raw is None else json.loads(_cipher.decrypt(raw))
