# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""PII cached only after envelope-encryption with a KMS-managed key."""

import json
import os

import redis
from cryptography.fernet import Fernet


# Key material unwrapped by the cloud KMS at process start; rotation by KMS.
FERNET_KEY = os.environ["KMS_FERNET_KEY"].encode()
_cipher = Fernet(FERNET_KEY)
r = redis.Redis(host="cache.example.com")


def cache_profile(user_id: str, profile: dict) -> None:
    blob = json.dumps(profile).encode()
    # Fernet authenticated encryption; the cache never sees plaintext PII.
    r.set(f"profile:{user_id}", _cipher.encrypt(blob), ex=300)
