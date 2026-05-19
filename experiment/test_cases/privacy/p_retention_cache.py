# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""User profile cache — no TTL configured."""

import redis

r = redis.Redis(host="cache.example.com", port=6379)


def cache_profile(user_id: str, profile: dict) -> None:
    # Stores full PII profile indefinitely — no expiry argument.
    r.set(f"profile:{user_id}", _serialize(profile))


def get_cached_profile(user_id: str) -> dict | None:
    raw = r.get(f"profile:{user_id}")
    if raw is None:
        return None
    return _deserialize(raw)


def _serialize(profile: dict) -> bytes:
    import json as _j

    return _j.dumps(profile).encode()


def _deserialize(raw: bytes) -> dict:
    import json as _j

    return _j.loads(raw)
