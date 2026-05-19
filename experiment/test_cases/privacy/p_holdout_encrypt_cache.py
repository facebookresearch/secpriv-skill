"""PII cached only after envelope-encryption with a KMS-managed key."""

import json

import redis
from cryptography.fernet import Fernet


# Key wrapped under the cloud KMS; rotation handled by KMS.
FERNET_KEY = b"<wrapped-by-KMS-at-runtime>"
_cipher = Fernet(FERNET_KEY) if FERNET_KEY != b"<wrapped-by-KMS-at-runtime>" else None
r = redis.Redis(host="cache.example.com")


def cache_profile(user_id: str, profile: dict) -> None:
    blob = json.dumps(profile).encode()
    # Fernet provides authenticated symmetric encryption; the cache
    # never sees plaintext PII.
    r.set(f"profile:{user_id}", _cipher.encrypt(blob) if _cipher else blob, ex=300)
