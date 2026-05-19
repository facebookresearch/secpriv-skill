# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""Profile cache with bounded TTL."""

import json

import redis

r = redis.Redis(host="cache.example.com", port=6379)
PROFILE_TTL_SECONDS = 300


def cache_profile(user_id: str, profile: dict) -> None:
    # Bounded retention — Redis evicts after PROFILE_TTL_SECONDS.
    r.set(f"profile:{user_id}", json.dumps(profile), ex=PROFILE_TTL_SECONDS)


def get_cached_profile(user_id: str) -> dict | None:
    raw = r.get(f"profile:{user_id}")
    return None if raw is None else json.loads(raw)
